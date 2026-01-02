import asyncio
import audioop
import inspect
import io
import json
import os
import uuid
import wave
from typing import Any, Optional

import httpx
from deepgram.clients.listen.v1.websocket.options import LiveOptions
from loguru import logger

from pipecat.audio.vad.silero import SileroVADAnalyzer
from pipecat.frames.frames import AggregationType, EndFrame, TTSAudioRawFrame, TTSTextFrame
from pipecat.pipeline.pipeline import Pipeline
from pipecat.pipeline.runner import PipelineRunner
from pipecat.pipeline.task import PipelineParams, PipelineTask
from pipecat.processors.aggregators.openai_llm_context import OpenAILLMContext
from pipecat.processors.frame_processor import FrameDirection, FrameProcessor
from pipecat.services.cartesia.tts import CartesiaTTSService
from pipecat.services.deepgram.stt import DeepgramSTTService
from pipecat.services.llm_service import FunctionCallParams
from pipecat.services.openai.llm import OpenAILLMService
from pipecat.transports.daily.transport import DailyDialinSettings, DailyParams, DailyTransport
from pipecat.utils.text.markdown_text_filter import MarkdownTextFilter


def _env(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return default if v is None else str(v)


def _require(name: str) -> str:
    v = _env(name, "").strip()
    if not v:
        raise RuntimeError(f"{name} not set")
    return v


def _parse_int(name: str, default: int) -> int:
    raw = _env(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _parse_float(name: str, default: float) -> float:
    raw = _env(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


_background_wav_cache: dict[tuple[str, int], bytes] = {}


async def _download_bytes_limited(url: str, *, max_bytes: int, timeout_s: float = 15.0) -> bytes:
    """Download content with a hard max size."""
    async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True) as client:
        async with client.stream("GET", url) as resp:
            resp.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes():
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise RuntimeError("Background audio file is too large")
                chunks.append(chunk)
            return b"".join(chunks)


def _wav_to_pcm16_mono(*, wav_bytes: bytes, target_sample_rate: int) -> bytes:
    """Convert a WAV file to PCM16 mono at the target sample rate."""
    with wave.open(io.BytesIO(wav_bytes), "rb") as wf:
        channels = int(wf.getnchannels())
        sampwidth = int(wf.getsampwidth())
        src_rate = int(wf.getframerate())
        nframes = int(wf.getnframes())
        pcm = wf.readframes(nframes)

    # Convert to 16-bit samples.
    if sampwidth != 2:
        pcm = audioop.lin2lin(pcm, sampwidth, 2)
        sampwidth = 2

    # Convert to mono.
    if channels == 2:
        pcm = audioop.tomono(pcm, sampwidth, 0.5, 0.5)
        channels = 1
    elif channels != 1:
        raise RuntimeError("Background WAV must be mono or stereo")

    # Resample if needed.
    if src_rate != target_sample_rate:
        pcm, _ = audioop.ratecv(pcm, sampwidth, channels, src_rate, target_sample_rate, None)

    # Ensure sample alignment.
    pcm = pcm[: len(pcm) - (len(pcm) % (sampwidth * channels))]
    return pcm


async def _load_background_pcm16_mono(*, url: str, target_sample_rate: int) -> bytes:
    """Load and cache a background WAV as PCM16 mono for mixing."""
    key = (url, int(target_sample_rate))
    if key in _background_wav_cache:
        return _background_wav_cache[key]

    if not url.lower().startswith("https://"):
        raise RuntimeError("Background audio URL must start with https://")

    raw = await _download_bytes_limited(url, max_bytes=5 * 1024 * 1024)
    pcm = _wav_to_pcm16_mono(wav_bytes=raw, target_sample_rate=target_sample_rate)
    if not pcm:
        raise RuntimeError("Background audio WAV contained no audio")

    _background_wav_cache[key] = pcm
    return pcm


class BackgroundTTSMixer(FrameProcessor):
    """Mixes a looped background track into TTSAudioRawFrame while the bot speaks."""

    def __init__(self, *, background_pcm16_mono: bytes, gain: float):
        super().__init__()
        self._bg = background_pcm16_mono or b""
        self._gain = float(gain)
        self._pos = 0

    def _next_bg(self, nbytes: int) -> bytes:
        if not self._bg or nbytes <= 0:
            return b"" if nbytes <= 0 else (b"\x00" * nbytes)

        out = bytearray()
        while len(out) < nbytes:
            if self._pos >= len(self._bg):
                self._pos = 0
            take = min(nbytes - len(out), len(self._bg) - self._pos)
            out.extend(self._bg[self._pos : self._pos + take])
            self._pos += take
        return bytes(out)

    async def process_frame(self, frame, direction: FrameDirection):
        await super().process_frame(frame, direction)

        if direction is FrameDirection.DOWNSTREAM and isinstance(frame, TTSAudioRawFrame):
            try:
                if self._gain > 0 and frame.audio:
                    bg = self._next_bg(len(frame.audio))
                    bg = audioop.mul(bg, 2, self._gain)
                    frame.audio = audioop.add(frame.audio, bg, 2)
                    frame.num_frames = int(len(frame.audio) / (frame.num_channels * 2))
            except Exception as e:
                logger.warning(f"Background mixer failed (disabling for this frame): {e}")

        await self.push_frame(frame, direction)


def _extract_dialin_settings(body: Any) -> Optional[DailyDialinSettings]:
    if not isinstance(body, dict):
        return None

    dialin = body.get("dialin_settings") or body.get("dialinSettings") or body.get("dialin")
    if not isinstance(dialin, dict):
        dialin = {}

    call_id = dialin.get("call_id") or dialin.get("callId") or body.get("call_id") or body.get("callId")
    call_domain = (
        dialin.get("call_domain")
        or dialin.get("callDomain")
        or body.get("call_domain")
        or body.get("callDomain")
    )

    if call_id and call_domain:
        return DailyDialinSettings(call_id=str(call_id), call_domain=str(call_domain))

    return None


def _extract_daily_api(body: Any) -> tuple[Optional[str], Optional[str]]:
    """Return (api_key, api_url) if present in request body or env."""
    api_key = None
    api_url = None

    if isinstance(body, dict):
        api_key = body.get("daily_api_key") or body.get("dailyApiKey")
        api_url = body.get("daily_api_url") or body.get("dailyApiUrl")

    api_key = (str(api_key).strip() if api_key else "") or _env("DAILY_API_KEY", "").strip() or None
    api_url = (
        (str(api_url).strip() if api_url else "")
        or _env("DAILY_API_URL", "https://api.daily.co/v1").strip()
        or None
    )

    return api_key, api_url


def _extract_session_mode(body: Any) -> str:
    """Return a lowercased mode string from the session body (if any)."""
    if not isinstance(body, dict):
        return ""
    mode = body.get("mode") or body.get("session_mode") or body.get("sessionMode")
    return str(mode or "").strip().lower()


_cartesia_default_voice_cache: Optional[str] = None


async def _resolve_cartesia_voice_id(*, api_key: str) -> str:
    """Resolve a usable Cartesia voice_id.

    Priority:
      1) CARTESIA_VOICE_ID
      2) CARTESIA_DEFAULT_VOICE_ID
      3) First voice returned by GET /voices?limit=1 (cached per process)
    """
    global _cartesia_default_voice_cache

    env_voice = _env("CARTESIA_VOICE_ID", "").strip()
    if env_voice:
        return env_voice

    env_default = _env("CARTESIA_DEFAULT_VOICE_ID", "").strip()
    if env_default:
        return env_default

    if _cartesia_default_voice_cache:
        return _cartesia_default_voice_cache

    base_url = (_env("CARTESIA_API_URL", "https://api.cartesia.ai").strip() or "https://api.cartesia.ai").rstrip(
        "/"
    )
    version = _env("CARTESIA_VERSION", "2025-04-16").strip() or "2025-04-16"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Cartesia-Version": version,
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0, headers=headers) as client:
            resp = await client.get(f"{base_url}/voices", params={"limit": 1})
            resp.raise_for_status()
            payload = resp.json()
    except Exception as e:
        raise RuntimeError(
            "CARTESIA_VOICE_ID not set and failed to auto-select a default voice from Cartesia /voices"
        ) from e

    voices = None
    if isinstance(payload, dict):
        voices = payload.get("data")
    elif isinstance(payload, list):
        voices = payload

    if not isinstance(voices, list) or not voices:
        raise RuntimeError("CARTESIA_VOICE_ID not set and Cartesia /voices returned no voices")

    first = voices[0]
    voice_id = first.get("id") if isinstance(first, dict) else None
    voice_id = str(voice_id).strip() if voice_id else ""
    if not voice_id:
        raise RuntimeError("CARTESIA_VOICE_ID not set and Cartesia /voices response was missing voice id")

    _cartesia_default_voice_cache = voice_id
    return voice_id


async def bot(session_args: Any):
    """Pipecat Cloud entrypoint.

    This bot is designed for Daily transport (including inbound telephony sessions).

    Required env vars (provided via Pipecat secret set):
      - DEEPGRAM_API_KEY
      - CARTESIA_API_KEY
      - XAI_API_KEY

    Optional env vars:
      - CARTESIA_VOICE_ID (preferred; per-agent)
      - CARTESIA_DEFAULT_VOICE_ID (fallback)
      - AGENT_GREETING
      - AGENT_PROMPT
      - XAI_MODEL (default: grok-3)
      - XAI_BASE_URL (default: https://api.x.ai/v1)
      - DEEPGRAM_MODEL (default: nova-3-general)
      - CARTESIA_MODEL (default: sonic-3)
      - AUDIO_SAMPLE_RATE (default: 16000)
      - DAILY_API_KEY / DAILY_API_URL (used for dial-in if provided)
      - CARTESIA_API_URL / CARTESIA_VERSION (used only for default voice resolution)
    """

    deepgram_key = _require("DEEPGRAM_API_KEY")
    cartesia_key = _require("CARTESIA_API_KEY")
    xai_key = _require("XAI_API_KEY")

    greeting = _env("AGENT_GREETING", "").strip()
    base_prompt = _env("AGENT_PROMPT", "You are a helpful voice assistant. Keep responses concise.").strip()

    # Tools configured via secret set
    operator_number = _env("OPERATOR_NUMBER", "").strip()

    # Background ambience (mixed into TTS audio while the bot speaks)
    background_audio_url = _env("BACKGROUND_AUDIO_URL", "").strip()
    background_audio_gain = _parse_float("BACKGROUND_AUDIO_GAIN", 0.06)

    # Portal integration (used for emailing templated documents)
    portal_base_url = _env("PORTAL_BASE_URL", "").strip().rstrip("/")
    portal_token = _env("PORTAL_AGENT_ACTION_TOKEN", "").strip()

    tools = []
    has_send_document_tool = False
    has_send_video_meeting_tool = False
    has_send_physical_mail_tool = False
    has_transfer_tool = False
    has_end_call_tool = False

    # End the call (hang up) when explicitly requested.
    tools.append(
        {
            "type": "function",
            "function": {
                "name": "end_call",
                "description": "End the current phone call (hang up). Only use when the caller explicitly asks or after you have confirmed they want to disconnect.",
                "parameters": {"type": "object", "properties": {}},
            },
        }
    )
    has_end_call_tool = True

    # Call transfer (cold transfer) - uses the configured OPERATOR_NUMBER destination.
    if operator_number:
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": "transfer_call",
                    "description": "Cold-transfer the caller to the configured transfer destination and leave the call.",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
        )
        has_transfer_tool = True

    if portal_base_url and portal_token:
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": "send_document",
                    "description": "Email a templated document to the caller using the business owner's SMTP settings and the agent's default template.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "to_email": {
                                "type": "string",
                                "description": "Recipient email address",
                            },
                            "subject": {
                                "type": "string",
                                "description": "Email subject (optional)",
                            },
                            "variables": {
                                "type": "object",
                                "description": "Template variables mapping. Keys correspond to placeholders inside [[...]] in the DOCX template (e.g. Name, Address).",
                            },
                        },
                        "required": ["to_email"],
                    },
                },
            }
        )
        has_send_document_tool = True

        tools.append(
            {
                "type": "function",
                "function": {
                    "name": "send_video_meeting_link",
                    "description": "Start a live video meeting and email the caller a Daily room link to join.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "to_email": {
                                "type": "string",
                                "description": "Recipient email address",
                            },
                            "subject": {
                                "type": "string",
                                "description": "Email subject (optional)",
                            },
                        },
                        "required": ["to_email"],
                    },
                },
            }
        )
        has_send_video_meeting_tool = True

        tools.append(
            {
                "type": "function",
                "function": {
                    "name": "send_physical_mail",
                    "description": "Send a physical letter via USPS to the caller using the business owner's return address and a template.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "to_name": {"type": "string", "description": "Recipient name"},
                            "to_organization": {"type": "string", "description": "Recipient organization (optional)"},
                            "to_address1": {"type": "string", "description": "Street address line 1"},
                            "to_address2": {"type": "string", "description": "Street address line 2 (optional)"},
                            "to_address3": {"type": "string", "description": "Street address line 3 (optional)"},
                            "to_city": {"type": "string", "description": "City"},
                            "to_state": {"type": "string", "description": "State (2-letter for US)"},
                            "to_postal_code": {"type": "string", "description": "ZIP / postal code"},
                            "to_country": {"type": "string", "description": "Country code (default: US)"},
                            "template_id": {"type": "integer", "description": "Optional template id override"},
                            "variables": {
                                "type": "object",
                                "description": "Template variables mapping. Keys correspond to placeholders inside [[...]] in the DOCX template (e.g. Name, Address).",
                            },
                        },
                        "required": ["to_address1", "to_city", "to_state", "to_postal_code"],
                    },
                },
            }
        )
        has_send_physical_mail_tool = True

    # Extend the user-provided prompt with minimal tool guidance.
    prompt = base_prompt
    if has_send_document_tool:
        prompt += (
            "\n\nYou can email the caller a document when requested. "
            "Collect their email and any details needed for the template placeholders, "
            "then call the send_document tool with to_email and variables. "
            "After the tool returns, confirm whether the email was sent."
        )
    if has_send_video_meeting_tool:
        prompt += (
            "\n\nIf the caller asks to switch to a video meeting, collect their email address "
            "and call the send_video_meeting_link tool with to_email. "
            "After the tool returns, tell them to open the link from their email to join."
        )
    if has_send_physical_mail_tool:
        prompt += (
            "\n\nIf the caller asks you to mail them a physical letter or document, collect their name and full mailing address "
            "(street, city, state, ZIP) and any details needed for the template placeholders, then call the "
            "send_physical_mail tool with the address fields and variables. "
            "After the tool returns, confirm the mail was submitted and (if provided) share the tracking number."
        )
    if has_end_call_tool:
        prompt += (
            "\n\nIf the caller explicitly asks you to end the phone call or hang up, "
            "confirm they want to disconnect, then call the end_call tool."
        )
    if has_transfer_tool:
        prompt += (
            "\n\nIf the caller asks to be transferred to a representative or operator, "
            "confirm they want to be transferred, then call the transfer_call tool."
        )

    room_url = getattr(session_args, "room_url", None) or getattr(session_args, "roomUrl", None) or ""
    token = getattr(session_args, "token", None) or getattr(session_args, "room_token", None) or ""
    if not room_url:
        raise RuntimeError(f"Missing room_url in session args: {type(session_args)}")

    sample_rate = _parse_int("AUDIO_SAMPLE_RATE", 16000)

    body = getattr(session_args, "body", None)
    dialin_settings = _extract_dialin_settings(body)
    daily_api_key, daily_api_url = _extract_daily_api(body)

    session_mode = _extract_session_mode(body)
    is_video_meeting = session_mode == "video_meeting"

    # Used for per-session transcript logging back to the portal
    call_id = str(dialin_settings.call_id) if dialin_settings else ""
    call_domain = str(dialin_settings.call_domain) if dialin_settings else ""

    daily_params = DailyParams(
        api_key=daily_api_key or "",
        api_url=daily_api_url or "https://api.daily.co/v1",
        dialin_settings=dialin_settings,
        audio_in_enabled=True,
        audio_out_enabled=True,
        audio_in_sample_rate=sample_rate,
        audio_out_sample_rate=sample_rate,
        # Enable video output only for explicit video meeting sessions.
        video_out_enabled=is_video_meeting,
        video_out_is_live=is_video_meeting,
        # NOTE: vad_enabled is deprecated in Pipecat 0.0.98; supplying a vad_analyzer is sufficient.
        vad_analyzer=SileroVADAnalyzer(),
    )

    # Daily Prebuilt always shows a participant name badge. To effectively "hide" the bot
    # name in video meetings, default to a zero-width space (U+200B).
    bot_name = _env("BOT_NAME", "")
    if bot_name == "":
        bot_name = "\u200B" if is_video_meeting else "TalkUSA AI Agent"

    transport = DailyTransport(
        room_url=str(room_url),
        token=str(token) if token else None,
        bot_name=bot_name,
        params=daily_params,
    )

    # STT / LLM / TTS
    deepgram_model = _env("DEEPGRAM_MODEL", "nova-3-general").strip()

    # Don't call stt.set_model() here: in Pipecat 0.0.98 it may assume an active
    # websocket connection and crash with "_connection" missing.
    # Instead, configure the model via Deepgram LiveOptions at construction.
    stt_live_options = LiveOptions(model=deepgram_model) if deepgram_model else None
    stt = DeepgramSTTService(
        api_key=deepgram_key,
        sample_rate=sample_rate,
        live_options=stt_live_options,
    )

    llm = OpenAILLMService(
        api_key=xai_key,
        # grok-beta was deprecated; default to grok-3.
        model=_env("XAI_MODEL", "grok-3").strip() or "grok-3",
        base_url=_env("XAI_BASE_URL", "https://api.x.ai/v1").strip() or "https://api.x.ai/v1",
    )

    # Register tool handler (if portal integration is configured)
    if has_send_document_tool:
        async def _send_document(params: FunctionCallParams) -> None:
            args = dict(params.arguments or {})
            to_email = str(args.get("to_email") or args.get("toEmail") or args.get("email") or "").strip()
            subject = str(args.get("subject") or "").strip()
            variables = args.get("variables") or {}
            if not isinstance(variables, dict):
                variables = {}

            if not to_email:
                await params.result_callback({"success": False, "message": "to_email is required"})
                return

            if not portal_base_url or not portal_token:
                await params.result_callback({
                    "success": False,
                    "message": "Portal integration not configured (missing PORTAL_BASE_URL or PORTAL_AGENT_ACTION_TOKEN)",
                })
                return

            payload: dict[str, Any] = {
                "to_email": to_email,
                "variables": variables,
            }
            if subject:
                payload["subject"] = subject

            if dialin_settings:
                payload["call_id"] = str(dialin_settings.call_id)
                payload["call_domain"] = str(dialin_settings.call_domain)

            url = f"{portal_base_url}/api/ai/agent/send-document"
            headers = {
                "Authorization": f"Bearer {portal_token}",
                "Accept": "application/json",
            }

            try:
                async with httpx.AsyncClient(timeout=20.0) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"success": False, "message": resp.text}

                if resp.status_code >= 400 or (isinstance(data, dict) and data.get("success") is False):
                    await params.result_callback({
                        "success": False,
                        "status_code": resp.status_code,
                        "response": data,
                    })
                    return

                await params.result_callback({"success": True, "response": data})
            except Exception as e:
                await params.result_callback({"success": False, "message": str(e)})

        llm.register_function("send_document", _send_document)

    if has_send_video_meeting_tool:
        async def _send_video_meeting_link(params: FunctionCallParams) -> None:
            args = dict(params.arguments or {})
            to_email = str(args.get("to_email") or args.get("toEmail") or args.get("email") or "").strip()
            subject = str(args.get("subject") or "").strip()

            if not to_email:
                await params.result_callback({"success": False, "message": "to_email is required"})
                return

            if not portal_base_url or not portal_token:
                await params.result_callback({
                    "success": False,
                    "message": "Portal integration not configured (missing PORTAL_BASE_URL or PORTAL_AGENT_ACTION_TOKEN)",
                })
                return

            payload: dict[str, Any] = {
                "to_email": to_email,
            }
            if subject:
                payload["subject"] = subject

            if dialin_settings:
                payload["call_id"] = str(dialin_settings.call_id)
                payload["call_domain"] = str(dialin_settings.call_domain)

            url = f"{portal_base_url}/api/ai/agent/send-video-meeting-link"
            headers = {
                "Authorization": f"Bearer {portal_token}",
                "Accept": "application/json",
            }

            try:
                async with httpx.AsyncClient(timeout=25.0) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"success": False, "message": resp.text}

                if resp.status_code >= 400 or (isinstance(data, dict) and data.get("success") is False):
                    await params.result_callback({
                        "success": False,
                        "status_code": resp.status_code,
                        "response": data,
                    })
                    return

                await params.result_callback({"success": True, "response": data})
            except Exception as e:
                await params.result_callback({"success": False, "message": str(e)})

        llm.register_function("send_video_meeting_link", _send_video_meeting_link)

    if has_send_physical_mail_tool:
        async def _send_physical_mail(params: FunctionCallParams) -> None:
            args = dict(params.arguments or {})

            # Address fields
            to_address1 = str(args.get("to_address1") or args.get("toAddress1") or args.get("address1") or "").strip()
            to_city = str(args.get("to_city") or args.get("toCity") or args.get("city") or "").strip()
            to_state = str(args.get("to_state") or args.get("toState") or args.get("state") or "").strip()
            to_postal_code = str(
                args.get("to_postal_code")
                or args.get("toPostalCode")
                or args.get("postal_code")
                or args.get("postalCode")
                or args.get("zip")
                or ""
            ).strip()

            to_name = str(args.get("to_name") or args.get("toName") or args.get("name") or "").strip()
            to_organization = str(args.get("to_organization") or args.get("toOrganization") or args.get("organization") or "").strip()
            to_address2 = str(args.get("to_address2") or args.get("toAddress2") or args.get("address2") or "").strip()
            to_address3 = str(args.get("to_address3") or args.get("toAddress3") or args.get("address3") or "").strip()
            to_country = str(args.get("to_country") or args.get("toCountry") or args.get("country") or "US").strip()

            template_id = args.get("template_id")
            if template_id is None:
                template_id = args.get("templateId")

            variables = args.get("variables") or {}
            if not isinstance(variables, dict):
                variables = {}

            if not to_address1 or not to_city or not to_state or not to_postal_code:
                await params.result_callback({
                    "success": False,
                    "message": "to_address1, to_city, to_state, and to_postal_code are required",
                })
                return

            if not portal_base_url or not portal_token:
                await params.result_callback({
                    "success": False,
                    "message": "Portal integration not configured (missing PORTAL_BASE_URL or PORTAL_AGENT_ACTION_TOKEN)",
                })
                return

            payload: dict[str, Any] = {
                "to_address1": to_address1,
                "to_city": to_city,
                "to_state": to_state,
                "to_postal_code": to_postal_code,
                "to_country": to_country or "US",
                "variables": variables,
            }

            if to_name:
                payload["to_name"] = to_name
            if to_organization:
                payload["to_organization"] = to_organization
            if to_address2:
                payload["to_address2"] = to_address2
            if to_address3:
                payload["to_address3"] = to_address3

            # Optional template override
            try:
                if template_id is not None and str(template_id).strip() != "":
                    payload["template_id"] = int(template_id)
            except Exception:
                # Ignore if not parseable; portal will validate
                pass

            if dialin_settings:
                payload["call_id"] = str(dialin_settings.call_id)
                payload["call_domain"] = str(dialin_settings.call_domain)

            url = f"{portal_base_url}/api/ai/agent/send-physical-mail"
            headers = {
                "Authorization": f"Bearer {portal_token}",
                "Accept": "application/json",
            }

            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"success": False, "message": resp.text}

                if resp.status_code >= 400 or (isinstance(data, dict) and data.get("success") is False):
                    await params.result_callback({
                        "success": False,
                        "status_code": resp.status_code,
                        "response": data,
                    })
                    return

                await params.result_callback({"success": True, "response": data})
            except Exception as e:
                await params.result_callback({"success": False, "message": str(e)})

        llm.register_function("send_physical_mail", _send_physical_mail)

    voice_id = await _resolve_cartesia_voice_id(api_key=cartesia_key)
    tts = CartesiaTTSService(
        api_key=cartesia_key,
        voice_id=voice_id,
        cartesia_version=_env("CARTESIA_VERSION", "2025-04-16").strip() or "2025-04-16",
        model=_env("CARTESIA_MODEL", "sonic-3").strip() or "sonic-3",
        sample_rate=sample_rate,
        text_filters=[MarkdownTextFilter()],
    )

    # Conversation context (OpenAI-compatible)
    if tools:
        context = OpenAILLMContext(
            messages=[{"role": "system", "content": prompt}] if prompt else [],
            tools=tools,
            tool_choice="auto",
        )
    else:
        context = OpenAILLMContext(messages=[{"role": "system", "content": prompt}] if prompt else [])

    # Optional: log conversation turns back to the portal for the dashboard UI.
    portal_log_client: Optional[httpx.AsyncClient] = None
    pending_log_tasks: set[asyncio.Task] = set()

    if portal_base_url and portal_token and call_id and call_domain:
        log_url = f"{portal_base_url}/api/ai/agent/log-message"
        headers = {
            "Authorization": f"Bearer {portal_token}",
            "Accept": "application/json",
        }
        portal_log_client = httpx.AsyncClient(timeout=5.0, headers=headers)

        async def _log_turn(role: str, content: str) -> None:
            if not portal_log_client:
                return
            text = str(content or "").strip()
            if not text:
                return
            if len(text) > 8000:
                text = text[:8000]
            payload = {
                "message_id": uuid.uuid4().hex,
                "role": role,
                "content": text,
                "call_id": call_id,
                "call_domain": call_domain,
            }
            try:
                await portal_log_client.post(log_url, json=payload)
            except Exception as e:
                # Best-effort; don't break the call if logging fails.
                logger.debug(f"Portal transcript log failed: {e}")

        orig_add = context.add_message

        def add_message_hook(msg: Any) -> None:
            try:
                if isinstance(msg, dict):
                    r = str(msg.get("role") or "").strip().lower()
                    if r in ("user", "assistant"):
                        c = msg.get("content")
                        t = asyncio.create_task(_log_turn(r, str(c or "")))
                        pending_log_tasks.add(t)
                        t.add_done_callback(lambda tt: pending_log_tasks.discard(tt))
            except Exception:
                pass
            return orig_add(msg)

        context.add_message = add_message_hook  # type: ignore

    ctx = llm.create_context_aggregator(context)

    # Optional: background ambience mixed into bot speech (TTSAudioRawFrame only).
    # For video meetings, we intentionally skip this so we don't feed background noise into
    # the avatar renderer (which can degrade lip-sync quality).
    bg_mixer = None
    if background_audio_url and not is_video_meeting:
        try:
            pcm = await _load_background_pcm16_mono(url=background_audio_url, target_sample_rate=sample_rate)
            bg_mixer = BackgroundTTSMixer(background_pcm16_mono=pcm, gain=background_audio_gain)
        except Exception as e:
            logger.warning(f"Background audio disabled: {e}")

    heygen_http_session = None
    heygen_service = None

    if is_video_meeting:
        heygen_key = _require("HEYGEN_API_KEY")
        try:
            import aiohttp
            from pipecat.frames.frames import UserStoppedSpeakingFrame
            from pipecat.services.heygen.api_interactive_avatar import NewSessionRequest
            from pipecat.services.heygen.video import HeyGenVideoService
        except Exception as e:
            raise RuntimeError("HeyGen dependencies missing. Install pipecat-ai[heygen].") from e

        avatar_id = _env("HEYGEN_AVATAR_ID", "Shawn_Therapist_public").strip() or "Shawn_Therapist_public"

        class ContinuousListeningHeyGenVideoService(HeyGenVideoService):
            async def start(self, frame):
                await super().start(frame)
                # Keep a continuous "listening" gesture when idle.
                try:
                    await self._client.start_agent_listening()
                except Exception:
                    pass

            async def process_frame(self, frame, direction: FrameDirection):
                # Don't send stop_listening; keep the idle listening gesture continuous.
                if isinstance(frame, UserStoppedSpeakingFrame):
                    await self.push_frame(frame, direction)
                    return
                await super().process_frame(frame, direction)

        heygen_http_session = aiohttp.ClientSession()
        heygen_service = ContinuousListeningHeyGenVideoService(
            api_key=heygen_key,
            session=heygen_http_session,
            session_request=NewSessionRequest(avatar_id=avatar_id, version="v2"),
        )

    # IMPORTANT: assistant context aggregator consumes TextFrames (it aggregates them and does
    # not forward). If it sits *before* TTS, the bot will generate text but you won't hear audio.
    # So we place it after TTS and before the output transport.
    steps = [
        transport.input(),
        stt,
        ctx.user(),
        llm,
        tts,
    ]
    if bg_mixer:
        steps.append(bg_mixer)
    if heygen_service:
        steps.append(heygen_service)
    steps.extend([
        ctx.assistant(),
        transport.output(),
    ])

    pipeline = Pipeline(steps)

    # Pipecat defaults to a 5-minute idle timeout, which is too short for the
    # "email a link and join" flow. Keep video meetings alive longer.
    idle_timeout_secs = 1800 if is_video_meeting else 300

    task = PipelineTask(
        pipeline,
        params=PipelineParams(
            allow_interruptions=True,
            audio_in_sample_rate=sample_rate,
            audio_out_sample_rate=sample_rate,
        ),
        idle_timeout_secs=idle_timeout_secs,
    )

    # Register tool handlers
    call_transfer_in_progress = False
    call_end_in_progress = False

    if has_end_call_tool:
        async def _end_call(params: FunctionCallParams) -> None:
            nonlocal call_end_in_progress

            if call_end_in_progress:
                await params.result_callback({
                    "success": False,
                    "message": "Call end already in progress",
                })
                return

            call_end_in_progress = True

            # Best-effort: for dial-in calls, eject the caller participant(s) so the PSTN leg disconnects.
            # For non-telephony sessions (e.g. video meetings), we just leave the room.
            eject_attempted = False
            eject_error: str | None = None

            try:
                if dialin_settings:
                    try:
                        participants = transport.participants() or {}

                        # Daily uses a special local key (often "local") plus UUID-like ids for remotes.
                        # The CallClient.update_remote_participants API expects remote participant IDs to be UUIDs.
                        my_id = str(getattr(transport, "participant_id", "") or "").strip()
                        local_ids = {"local"}
                        if my_id:
                            local_ids.add(my_id)

                        for pid, info in participants.items():
                            if not isinstance(info, dict):
                                continue
                            if info.get("local") or info.get("isLocal") or info.get("is_local"):
                                if pid:
                                    local_ids.add(str(pid))

                        def _is_uuid_like(value: Any) -> bool:
                            try:
                                uuid.UUID(str(value))
                                return True
                            except Exception:
                                return False

                        remote_ids = [
                            pid
                            for pid in participants.keys()
                            if pid and str(pid) not in local_ids and _is_uuid_like(pid)
                        ]

                        if remote_ids:
                            eject_attempted = True
                            remote_participants = {str(pid): {"eject": True} for pid in remote_ids}
                            err = await transport.update_remote_participants(remote_participants)
                            if err:
                                eject_error = str(err)
                    except Exception as e:
                        eject_error = str(e)

                await params.result_callback({
                    "success": True,
                    "eject_attempted": eject_attempted,
                    "eject_error": eject_error,
                })
            except Exception as e:
                await params.result_callback({
                    "success": False,
                    "message": str(e),
                })
            finally:
                # Stop the pipeline and leave the room.
                try:
                    await task.queue_frames([EndFrame()])
                except Exception:
                    pass
                try:
                    await transport.leave()
                except Exception:
                    pass

        llm.register_function("end_call", _end_call)

    if has_transfer_tool:
        async def _transfer_call(params: FunctionCallParams) -> None:
            nonlocal call_transfer_in_progress

            if call_transfer_in_progress:
                await params.result_callback({
                    "success": False,
                    "message": "Transfer already in progress",
                })
                return

            if not operator_number:
                await params.result_callback({
                    "success": False,
                    "message": "Transfer destination not configured",
                })
                return

            call_transfer_in_progress = True

            # Try SIP REFER first (exits Daily media path), then fall back to call transfer.
            # NOTE: sip_refer requires an explicit sessionId. Pipecat auto-fills sessionId for
            # sip_call_transfer, but not for sip_refer.
            session_id = ""
            try:
                client = getattr(transport, "_client", None)
                if client is not None:
                    session_id = (
                        str(getattr(client, "_dial_out_session_id", "") or "").strip()
                        or str(getattr(client, "_dial_in_session_id", "") or "").strip()
                    )
            except Exception:
                session_id = ""

            refer_settings = {"toEndPoint": operator_number}
            if session_id:
                refer_settings["sessionId"] = session_id

            try:
                error = None

                if session_id:
                    error = await transport.sip_refer(refer_settings)
                else:
                    error = "Missing sessionId for SIP REFER"

                if error:
                    logger.warning(f"sip_refer failed, falling back to sip_call_transfer: {error}")
                    error = await transport.sip_call_transfer({"toEndPoint": operator_number})

                if error:
                    call_transfer_in_progress = False
                    await params.result_callback({"success": False, "message": str(error)})
                    return

                # We successfully initiated the transfer; end the bot's pipeline.
                await params.result_callback({"success": True})

                # Stop the pipeline and leave the room so the bot disconnects.
                await task.queue_frames([EndFrame()])
                try:
                    await transport.leave()
                except Exception:
                    pass
            except Exception as e:
                call_transfer_in_progress = False
                await params.result_callback({"success": False, "message": str(e)})

        llm.register_function("transfer_call", _transfer_call)

    # Speak first (direct TTS), once.
    if greeting:
        greeted = False

        @transport.event_handler("on_first_participant_joined")
        async def on_first_participant_joined(_transport, _participant):
            nonlocal greeted
            if greeted:
                return
            greeted = True
            try:
                context.add_message({"role": "assistant", "content": greeting})
            except Exception:
                pass
            await task.queue_frames([TTSTextFrame(greeting, aggregated_by=AggregationType.SENTENCE)])

    runner = PipelineRunner()
    try:
        await runner.run(task)
    finally:
        # Best-effort: flush a few pending transcript log tasks.
        try:
            if pending_log_tasks:
                await asyncio.wait(pending_log_tasks, timeout=2.0)
        except Exception:
            pass
        if portal_log_client:
            try:
                await portal_log_client.aclose()
            except Exception:
                pass
        if heygen_http_session:
            try:
                await heygen_http_session.close()
            except Exception:
                pass
