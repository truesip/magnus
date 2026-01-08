import asyncio
import audioop
import inspect
import io
import json
import os
import re
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
      - XAI_API_KEY

    Required env vars for audio TTS (phone calls and HeyGen video meetings):
      - CARTESIA_API_KEY

    Required env vars for Akool video meetings (VIDEO_AVATAR_PROVIDER=akool):
      - AKOOL_API_KEY
      - AKOOL_AVATAR_ID

    Optional env vars:
      - CARTESIA_VOICE_ID (preferred; per-agent)
      - CARTESIA_DEFAULT_VOICE_ID (fallback)
      - AGENT_GREETING
      - AGENT_PROMPT
      - XAI_MODEL (default: grok-3)
      - XAI_BASE_URL (default: https://api.x.ai/v1)
      - AKOOL_VISION_LLM_MODEL (default: grok-4; used only when AKOOL_VISION_LLM_ENABLED=1)
      - DEEPGRAM_MODEL (default: nova-3-general)
      - CARTESIA_MODEL (default: sonic-3)
      - AUDIO_SAMPLE_RATE (default: 16000)
      - DAILY_API_KEY / DAILY_API_URL (used for dial-in if provided)
      - CARTESIA_API_URL / CARTESIA_VERSION (used only for default voice resolution)
    """

    deepgram_key = _require("DEEPGRAM_API_KEY")
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
    has_send_custom_email_tool = False
    has_send_video_meeting_tool = False
    has_send_physical_mail_tool = False
    has_send_custom_physical_mail_tool = False
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
                    "description": "Email a templated document (DOCX/PDF attachment) to the caller using the business owner's SMTP settings and the agent's default template.",
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
                    "name": "send_custom_email",
                    "description": "Send a custom email to the caller (no template, no attachments). Use this when the caller asks you to email them information.",
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
                            "body": {
                                "type": "string",
                                "description": "Plain-text email body",
                            },
                        },
                        "required": ["to_email", "body"],
                    },
                },
            }
        )
        has_send_custom_email_tool = True

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

        tools.append(
            {
                "type": "function",
                "function": {
                    "name": "send_custom_physical_mail",
                    "description": "Send a custom physical letter via USPS (no template). Use this when the caller asks you to mail them a letter with custom text.",
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
                            "subject": {"type": "string", "description": "Letter subject/title (optional)"},
                            "body": {"type": "string", "description": "Letter body text"},
                        },
                        "required": ["to_address1", "to_city", "to_state", "to_postal_code", "body"],
                    },
                },
            }
        )
        has_send_custom_physical_mail_tool = True

    # Extend the user-provided prompt with minimal tool guidance.
    prompt = base_prompt
    if has_send_custom_email_tool:
        prompt += (
            "\n\nIf the caller asks you to email them information, collect their email address and confirm what they want sent. "
            "Then call the send_custom_email tool with to_email, an optional subject, and a clear plain-text body. "
            "After the tool returns, confirm whether the email was sent."
        )
    if has_send_document_tool:
        prompt += (
            "\n\nIf the caller asks for a formal document attachment that must be generated from a template, "
            "collect their email and any details needed for template placeholders, then call the send_document tool. "
            "After the tool returns, confirm whether the email was sent."
        )
    if has_send_video_meeting_tool:
        prompt += (
            "\n\nIf the caller asks to switch to a video meeting, collect their email address "
            "and call the send_video_meeting_link tool with to_email. "
            "After the tool returns, tell them to open the link from their email to join."
        )
    if has_send_custom_physical_mail_tool:
        prompt += (
            "\n\nIf the caller asks you to mail them a physical letter with custom text, collect their name and full mailing address "
            "(street, city, state, ZIP) and confirm the letter content you will send. Then call the send_custom_physical_mail tool "
            "with the address fields and body. After the tool returns, if success is true confirm the mail was submitted and share the "
            "tracking number if present. If success is false, clearly say the mail was NOT sent/submitted and do not claim it was sent. "
            "Do not discuss internal billing, costs, or refunds with the caller."
        )
    if has_send_physical_mail_tool:
        prompt += (
            "\n\nIf the caller asks you to mail them a templated physical document/letter, collect their name and full mailing address "
            "(street, city, state, ZIP) and any details needed for the template placeholders, then call the send_physical_mail tool. "
            "After the tool returns, check the tool result: if success is true, confirm the mail was submitted and share the tracking number "
            "if present. If success is false, clearly say the mail was NOT sent/submitted and do not claim it was sent. Do not discuss internal "
            "billing, costs, or refunds with the caller."
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

    caller_memory = None
    try:
        if isinstance(body, dict):
            caller_memory = body.get("caller_memory") or body.get("callerMemory")
    except Exception:
        caller_memory = None

    session_mode = _extract_session_mode(body)
    is_video_meeting = session_mode == "video_meeting"

    # Video avatar selection (video meetings only)
    video_avatar_provider = _env("VIDEO_AVATAR_PROVIDER", "heygen").strip().lower()
    if not video_avatar_provider:
        video_avatar_provider = "heygen"
    if not is_video_meeting:
        video_avatar_provider = "none"

    # Akool "Vision Sense" (two-way video) support.
    # When enabled, we capture the first participant's camera frames from Daily and (optionally)
    # publish them into Akool's LiveKit room so the avatar can "see" the user's camera feed.
    akool_vision_enabled = (
        _env("AKOOL_VISION_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")
    )
    akool_vision_fps = max(1, _parse_int("AKOOL_VISION_FPS", 3))

    # Optional: attach the latest captured camera frame to the LLM so the assistant can
    # answer questions based on what it "sees".
    akool_vision_llm_enabled = (
        _env("AKOOL_VISION_LLM_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")
    )
    akool_vision_llm_max_age_s = min(60.0, max(0.0, _parse_float("AKOOL_VISION_LLM_MAX_AGE_S", 5.0)))

    # Performance tuning: attaching an image to every turn can slow response latency.
    #
    # Modes:
    #  - always: attach the latest camera frame to every user turn
    #  - auto: attach only when the user's text likely requires vision (faster)
    #  - never: never attach images (equivalent to AKOOL_VISION_LLM_ENABLED=0)
    akool_vision_llm_attach_mode = (_env("AKOOL_VISION_LLM_ATTACH_MODE", "always").strip().lower() or "always")
    if akool_vision_llm_attach_mode not in ("always", "auto", "never"):
        akool_vision_llm_attach_mode = "always"

    # Downscale/compress the attached image before sending to the LLM (reduces payload + latency).
    akool_vision_llm_max_dim = max(0, min(2048, _parse_int("AKOOL_VISION_LLM_MAX_DIM", 512)))
    akool_vision_llm_jpeg_quality = max(30, min(95, _parse_int("AKOOL_VISION_LLM_JPEG_QUALITY", 65)))

    # We only turn on Daily video input if at least one vision feature is enabled.
    akool_vision_capture_enabled = bool(akool_vision_enabled or akool_vision_llm_enabled)

    if is_video_meeting and video_avatar_provider == "akool" and akool_vision_llm_enabled:
        prompt += (
            "\n\nYou are in a video meeting. You may receive still images from the user's camera. "
            "Use them when relevant to answer questions about what you see. "
            "If no recent image is available, say you can't see the camera right now."
        )

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
        # Enable video input only when explicitly requested (Akool Vision Sense).
        video_in_enabled=bool(is_video_meeting and video_avatar_provider == "akool" and akool_vision_capture_enabled),
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

    class RoutingOpenAILLMService(OpenAILLMService):
        def __init__(self, *, text_model: str, vision_model: str, **kwargs):
            self._text_model_name = str(text_model or "").strip()
            self._vision_model_name = str(vision_model or "").strip()
            super().__init__(model=self._text_model_name, **kwargs)

        def build_chat_completion_params(self, params_from_context):
            params = super().build_chat_completion_params(params_from_context)

            # Route to vision model only when an image is present in the message content.
            model = self._text_model_name
            try:
                messages = None
                if isinstance(params_from_context, dict):
                    messages = params_from_context.get("messages")
                if not isinstance(messages, list):
                    messages = []

                for msg in messages:
                    if not isinstance(msg, dict):
                        continue
                    content = msg.get("content")
                    if not isinstance(content, list):
                        continue
                    for item in content:
                        if not isinstance(item, dict):
                            continue
                        if str(item.get("type") or "").strip().lower() == "image_url":
                            model = self._vision_model_name
                            raise StopIteration
            except StopIteration:
                pass
            except Exception:
                pass

            params["model"] = model
            return params

    xai_text_model = _env("XAI_MODEL", "grok-3").strip() or "grok-3"
    xai_base_url = _env("XAI_BASE_URL", "https://api.x.ai/v1").strip() or "https://api.x.ai/v1"

    if is_video_meeting and video_avatar_provider == "akool" and akool_vision_llm_enabled:
        xai_vision_model = _env("AKOOL_VISION_LLM_MODEL", "grok-4").strip() or "grok-4"
        llm = RoutingOpenAILLMService(
            api_key=xai_key,
            text_model=xai_text_model,
            vision_model=xai_vision_model,
            base_url=xai_base_url,
        )
    else:
        llm = OpenAILLMService(
            api_key=xai_key,
            # grok-beta was deprecated; default to grok-3.
            model=xai_text_model,
            base_url=xai_base_url,
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

    if has_send_custom_email_tool:
        async def _send_custom_email(params: FunctionCallParams) -> None:
            args = dict(params.arguments or {})
            to_email = str(args.get("to_email") or args.get("toEmail") or args.get("email") or "").strip()
            subject = str(args.get("subject") or "").strip()
            body = str(args.get("body") or args.get("text") or args.get("message") or "").strip()

            if not to_email:
                await params.result_callback({"success": False, "message": "to_email is required"})
                return
            if not body:
                await params.result_callback({"success": False, "message": "body is required"})
                return

            if not portal_base_url or not portal_token:
                await params.result_callback({
                    "success": False,
                    "message": "Portal integration not configured (missing PORTAL_BASE_URL or PORTAL_AGENT_ACTION_TOKEN)",
                })
                return

            payload: dict[str, Any] = {
                "to_email": to_email,
                "text": body,
            }
            if subject:
                payload["subject"] = subject

            if dialin_settings:
                payload["call_id"] = str(dialin_settings.call_id)
                payload["call_domain"] = str(dialin_settings.call_domain)

            url = f"{portal_base_url}/api/ai/agent/send-email"
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

        llm.register_function("send_custom_email", _send_custom_email)

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
                    # Return a sanitized error payload (avoid leaking internal billing/refund details).
                    err_msg = ""
                    if isinstance(data, dict):
                        err_msg = str(data.get("message") or data.get("error") or "").strip()
                    if not err_msg:
                        err_msg = str(resp.text or "").strip()
                    if not err_msg:
                        err_msg = "Physical mail request failed"

                    await params.result_callback({
                        "success": False,
                        "status_code": resp.status_code,
                        "message": err_msg,
                    })
                    return

                # Success: return a minimal payload to the LLM.
                out: dict[str, Any] = {"success": True}
                if isinstance(data, dict):
                    out["already_sent"] = bool(data.get("already_sent") or data.get("alreadySent") or False)
                    batch_id = data.get("batch_id") or data.get("batchId")
                    tracking_number = data.get("tracking_number") or data.get("trackingNumber")
                    if batch_id:
                        out["batch_id"] = str(batch_id)
                    if tracking_number:
                        out["tracking_number"] = str(tracking_number)

                await params.result_callback(out)
            except Exception as e:
                await params.result_callback({"success": False, "message": str(e)})

        llm.register_function("send_physical_mail", _send_physical_mail)

    if has_send_custom_physical_mail_tool:
        async def _send_custom_physical_mail(params: FunctionCallParams) -> None:
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

            subject = str(args.get("subject") or "").strip()
            body = str(args.get("body") or args.get("text") or args.get("message") or "").strip()

            if not to_address1 or not to_city or not to_state or not to_postal_code:
                await params.result_callback({
                    "success": False,
                    "message": "to_address1, to_city, to_state, and to_postal_code are required",
                })
                return
            if not body:
                await params.result_callback({"success": False, "message": "body is required"})
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
                "body": body,
            }

            if subject:
                payload["subject"] = subject
            if to_name:
                payload["to_name"] = to_name
            if to_organization:
                payload["to_organization"] = to_organization
            if to_address2:
                payload["to_address2"] = to_address2
            if to_address3:
                payload["to_address3"] = to_address3

            if dialin_settings:
                payload["call_id"] = str(dialin_settings.call_id)
                payload["call_domain"] = str(dialin_settings.call_domain)

            url = f"{portal_base_url}/api/ai/agent/send-custom-physical-mail"
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
                    err_msg = ""
                    if isinstance(data, dict):
                        err_msg = str(data.get("message") or data.get("error") or "").strip()
                    if not err_msg:
                        err_msg = str(resp.text or "").strip()
                    if not err_msg:
                        err_msg = "Physical mail request failed"

                    await params.result_callback({
                        "success": False,
                        "status_code": resp.status_code,
                        "message": err_msg,
                    })
                    return

                out: dict[str, Any] = {"success": True}
                if isinstance(data, dict):
                    out["already_sent"] = bool(data.get("already_sent") or data.get("alreadySent") or False)
                    batch_id = data.get("batch_id") or data.get("batchId")
                    tracking_number = data.get("tracking_number") or data.get("trackingNumber")
                    if batch_id:
                        out["batch_id"] = str(batch_id)
                    if tracking_number:
                        out["tracking_number"] = str(tracking_number)

                await params.result_callback(out)
            except Exception as e:
                await params.result_callback({"success": False, "message": str(e)})

        llm.register_function("send_custom_physical_mail", _send_custom_physical_mail)

    # TTS is required for phone calls and for HeyGen video meetings.
    # For Akool video meetings, Akool generates audio/video from stream messages, so we do not run TTS.
    tts = None
    if not (is_video_meeting and video_avatar_provider == "akool"):
        cartesia_key = _require("CARTESIA_API_KEY")
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
    messages = [{"role": "system", "content": prompt}] if prompt else []

    # If the portal provided caller memory, prepend it as prior conversation history.
    try:
        if isinstance(caller_memory, dict):
            meta = str(caller_memory.get("meta") or "").strip()
            mem = caller_memory.get("messages")
            if isinstance(mem, list):
                mem_msgs = []
                for m in mem[:50]:
                    if not isinstance(m, dict):
                        continue
                    role = str(m.get("role") or "").strip().lower()
                    if role not in ("user", "assistant"):
                        continue
                    content = str(m.get("content") or "").strip()
                    if not content:
                        continue
                    if len(content) > 2000:
                        content = content[:2000]
                    mem_msgs.append({"role": role, "content": content})

                if mem_msgs:
                    messages.append({
                        "role": "system",
                        "content": meta
                        or "Returning caller: the following messages are from a previous call with this caller. Use them as context.",
                    })
                    messages.extend(mem_msgs)
    except Exception:
        pass

    if tools:
        context = OpenAILLMContext(
            messages=messages,
            tools=tools,
            tool_choice="auto",
        )
    else:
        context = OpenAILLMContext(messages=messages)

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
            def _content_for_log(content: Any) -> str:
                # Avoid logging data:image/jpeg;base64,... blobs (vision messages).
                try:
                    if isinstance(content, str):
                        return content
                    if isinstance(content, list):
                        parts: list[str] = []
                        for item in content:
                            if not isinstance(item, dict):
                                continue
                            typ = str(item.get("type") or "").strip().lower()
                            if typ == "text":
                                t = str(item.get("text") or "").strip()
                                if t:
                                    parts.append(t)
                            elif typ == "image_url":
                                parts.append("[image]")
                            elif typ:
                                parts.append(f"[{typ}]")
                        return "\n".join([p for p in parts if p]).strip()
                    return str(content or "")
                except Exception:
                    return ""

            try:
                if isinstance(msg, dict):
                    r = str(msg.get("role") or "").strip().lower()
                    if r in ("user", "assistant"):
                        c = msg.get("content")
                        t = asyncio.create_task(_log_turn(r, _content_for_log(c)))
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
    akool_service = None

    if is_video_meeting and video_avatar_provider == "heygen":
        heygen_key = _require("HEYGEN_API_KEY")
        try:
            import aiohttp
            from pipecat.frames.frames import UserStoppedSpeakingFrame
            from pipecat.services.heygen.api_interactive_avatar import NewSessionRequest
            from pipecat.services.heygen.video import AVATAR_VAD_STOP_SECS, HeyGenVideoService
        except Exception as e:
            raise RuntimeError("HeyGen dependencies missing. Install pipecat-ai[heygen].") from e

        avatar_id = _env("HEYGEN_AVATAR_ID", "Shawn_Therapist_public").strip() or "Shawn_Therapist_public"

        class ContinuousListeningHeyGenVideoService(HeyGenVideoService):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._audio_only_fallback = False
                self._fallback_reason = ""
                self._fallback_shutdown_task: asyncio.Task | None = None

            async def _enter_audio_only_fallback(self, reason: str, exception: Exception | None = None):
                if self._audio_only_fallback:
                    return

                self._audio_only_fallback = True
                self._fallback_reason = str(reason or "").strip()

                msg = (
                    "HeyGen avatar unavailable, falling back to audio-only for this meeting"
                    + (f": {self._fallback_reason}" if self._fallback_reason else "")
                )
                if exception:
                    msg += f" ({exception})"
                logger.warning(msg)

                async def _shutdown():
                    # Best-effort: stop HeyGen connections/tasks to avoid noisy retries.
                    try:
                        await self._end_conversation()
                    except Exception:
                        pass
                    try:
                        await self._cancel_send_task()
                    except Exception:
                        pass

                if not self._fallback_shutdown_task:
                    try:
                        self._fallback_shutdown_task = self.create_task(_shutdown(), name="heygen_fallback_shutdown")
                    except Exception:
                        try:
                            self._fallback_shutdown_task = asyncio.create_task(_shutdown())
                        except Exception:
                            pass

            async def start(self, frame):
                try:
                    await super().start(frame)
                except Exception as e:
                    await self._enter_audio_only_fallback(f"start failed: {e}", exception=e)
                    return

                # Keep a continuous "listening" gesture when idle.
                if not self._audio_only_fallback:
                    try:
                        await self._client.start_agent_listening()
                    except Exception:
                        pass

            async def _on_participant_video_frame(self, video_frame):
                if self._audio_only_fallback:
                    return
                await super()._on_participant_video_frame(video_frame)

            async def _on_participant_audio_data(self, audio_frame):
                if self._audio_only_fallback:
                    return
                await super()._on_participant_audio_data(audio_frame)

            async def _send_task_handler(self):
                # Override to catch websocket/livekit send errors and fail over to audio-only.
                sample_rate = self._client.out_sample_rate
                audio_buffer = bytearray()
                self._event_id = None

                while True:
                    try:
                        frame = await asyncio.wait_for(self._queue.get(), timeout=AVATAR_VAD_STOP_SECS)
                        if self._audio_only_fallback:
                            return
                        if self._is_interrupting:
                            break
                        if isinstance(frame, TTSAudioRawFrame):
                            # starting the new inference
                            if self._event_id is None:
                                self._event_id = str(frame.id)

                            audio = await self._resampler.resample(frame.audio, frame.sample_rate, sample_rate)
                            audio_buffer.extend(audio)
                            while len(audio_buffer) >= self._audio_chunk_size:
                                chunk = audio_buffer[: self._audio_chunk_size]
                                audio_buffer = audio_buffer[self._audio_chunk_size :]
                                try:
                                    await self._client.agent_speak(bytes(chunk), self._event_id)
                                except Exception as e:
                                    await self._enter_audio_only_fallback(f"agent_speak failed: {e}", exception=e)
                                    return
                        self._queue.task_done()
                    except asyncio.TimeoutError:
                        # Bot has stopped speaking
                        if self._event_id is not None:
                            try:
                                await self._client.agent_speak_end(self._event_id)
                            except Exception as e:
                                await self._enter_audio_only_fallback(f"agent_speak_end failed: {e}", exception=e)
                                return
                            self._event_id = None
                            audio_buffer.clear()
                    except Exception as e:
                        await self._enter_audio_only_fallback(f"send loop error: {e}", exception=e)
                        return

            async def process_frame(self, frame, direction: FrameDirection):
                # Audio-only fallback: passthrough everything (let Daily output play TTS audio).
                if self._audio_only_fallback:
                    await self.push_frame(frame, direction)
                    return

                # If the internal send task crashed, switch to audio-only.
                if self._send_task and self._send_task.done():
                    exc = None
                    try:
                        exc = self._send_task.exception()
                    except Exception:
                        exc = None
                    await self._enter_audio_only_fallback(
                        f"send task ended unexpectedly: {exc or 'unknown'}",
                        exception=exc if isinstance(exc, Exception) else None,
                    )
                    await self.push_frame(frame, direction)
                    return

                # Don't send stop_listening; keep the idle listening gesture continuous.
                if isinstance(frame, UserStoppedSpeakingFrame):
                    await self.push_frame(frame, direction)
                    return

                # If we're supposed to be using HeyGen but we're not connected, fail over.
                if isinstance(frame, TTSAudioRawFrame):
                    if not getattr(self._client, "_connected", False):
                        await self._enter_audio_only_fallback("websocket not connected")
                        await self.push_frame(frame, direction)
                        return

                await super().process_frame(frame, direction)

        heygen_http_session = aiohttp.ClientSession()
        heygen_service = ContinuousListeningHeyGenVideoService(
            api_key=heygen_key,
            session=heygen_http_session,
            session_request=NewSessionRequest(avatar_id=avatar_id, version="v2"),
        )

    if is_video_meeting and video_avatar_provider == "akool":
        try:
            from livekit import rtc
            from livekit.rtc._proto.video_frame_pb2 import VideoBufferType
        except Exception as e:
            raise RuntimeError("Akool LiveKit dependencies missing. Install pipecat-ai[heygen] or livekit.") from e

        from pipecat.frames.frames import (
            CancelFrame,
            EndFrame as PipecatEndFrame,
            Frame,
            InterruptionFrame,
            LLMFullResponseEndFrame,
            LLMTextFrame,
            OutputTransportReadyFrame,
            SpeechOutputAudioRawFrame,
            StartFrame,
            TTSTextFrame as PipecatTTSTextFrame,
            UserImageRawFrame,
            UserStartedSpeakingFrame,
            OutputImageRawFrame,
        )

        akool_api_key = _require("AKOOL_API_KEY")
        akool_avatar_id = _require("AKOOL_AVATAR_ID")

        akool_base_url = (_env("AKOOL_API_BASE_URL", "https://openapi.akool.com").strip() or "https://openapi.akool.com").rstrip("/")
        akool_voice_id = _env("AKOOL_VOICE_ID", "").strip()
        akool_background_id = _env("AKOOL_BACKGROUND_ID", "").strip()
        akool_mode_type = _parse_int("AKOOL_MODE_TYPE", 1)  # 1=retelling, 2=dialogue
        akool_duration = _parse_int("AKOOL_DURATION_SECONDS", 1800)

        # Vision Sense / two-way video: send Daily participant camera frames to Akool.
        akool_vision_enabled = bool(akool_vision_enabled)
        akool_vision_fps = int(akool_vision_fps)

        class AkoolVideoService(FrameProcessor):
            def __init__(
                self,
                *,
                api_key: str,
                base_url: str,
                avatar_id: str,
                voice_id: str = "",
                background_id: str = "",
                mode_type: int = 1,
                duration_seconds: int = 1800,
                out_sample_rate: int = 16000,
                vision_enabled: bool = False,
                vision_fps: int = 3,
            ):
                super().__init__()
                self._api_key = str(api_key)
                self._base_url = str(base_url).rstrip("/")
                self._avatar_id = str(avatar_id)
                self._voice_id = str(voice_id or "")
                self._background_id = str(background_id or "")
                self._mode_type = int(mode_type) if int(mode_type) in (1, 2) else 1
                self._duration_seconds = max(30, int(duration_seconds) if int(duration_seconds) > 0 else 1800)

                self._out_sample_rate = int(out_sample_rate) if int(out_sample_rate) > 0 else 16000
                self._audio_ratecv_state = None

                # Vision Sense (optional): publish a local video track to Akool's LiveKit room.
                self._vision_enabled = bool(vision_enabled)
                self._vision_fps = max(1, int(vision_fps) if int(vision_fps) > 0 else 3)
                self._vision_lock = asyncio.Lock()
                self._vision_source: rtc.VideoSource | None = None
                self._vision_track: rtc.LocalVideoTrack | None = None
                self._vision_width: int = 0
                self._vision_height: int = 0
                self._vision_last_sent_s: float = 0.0

                # Route LiveKit media frames to the same output destination as the pipeline.
                self._transport_destination = None

                self._http: httpx.AsyncClient | None = None
                self._session_id: str = ""

                self._room: rtc.Room | None = None
                self._livekit_url: str = ""
                self._livekit_token: str = ""
                self._livekit_room_name: str = ""
                self._server_identity: str = ""

                self._task_manager = None
                self._transport_ready = False

                self._audio_task = None
                self._video_task = None

                self._pending_text = ""
                self._send_lock = asyncio.Lock()
                self._current_mid: str | None = None

                self._disabled = False
                self._disabled_reason = ""
                self._shutdown_lock = asyncio.Lock()
                self._shutdown_task: asyncio.Task | None = None

            async def setup(self, setup):
                await super().setup(setup)
                self._task_manager = getattr(setup, "task_manager", None)

                headers = {
                    "x-api-key": self._api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                }
                self._http = httpx.AsyncClient(timeout=20.0, headers=headers)

            async def cleanup(self):
                try:
                    await self._stop_session()
                finally:
                    if self._http:
                        try:
                            await self._http.aclose()
                        except Exception:
                            pass
                        self._http = None
                await super().cleanup()

            async def _create_session(self):
                if not self._http:
                    raise RuntimeError("Akool HTTP client not initialized")

                payload: dict[str, Any] = {
                    "avatar_id": self._avatar_id,
                    "stream_type": "livekit",
                    "mode_type": self._mode_type,
                    "duration": self._duration_seconds,
                }
                if self._voice_id:
                    payload["voice_id"] = self._voice_id
                if self._background_id:
                    payload["background_id"] = self._background_id

                url = f"{self._base_url}/api/open/v4/liveAvatar/session/create"
                resp = await self._http.post(url, json=payload)
                data = None
                try:
                    data = resp.json()
                except Exception:
                    data = None

                if resp.status_code >= 400:
                    raise RuntimeError(f"Akool session create failed (HTTP {resp.status_code}): {resp.text}")

                if not isinstance(data, dict):
                    raise RuntimeError("Akool session create returned non-JSON response")

                # Typical response: {"code":1000,"msg":"ok","data":{...}}
                code = data.get("code")
                msg = data.get("msg")

                payload_data_raw = data.get("data")
                payload_data: dict[str, Any] = {}
                if isinstance(payload_data_raw, dict):
                    payload_data = payload_data_raw
                elif isinstance(payload_data_raw, list) and payload_data_raw and isinstance(payload_data_raw[0], dict):
                    payload_data = payload_data_raw[0]

                if code not in (1000, "1000", 0, "0", None):
                    raise RuntimeError(f"Akool session create error: code={code} msg={msg}")

                # Helper: traverse nested dict/list and find values without logging secrets.
                def _walk(obj: Any, path: list[Any] | None = None, depth: int = 0, max_depth: int = 6):
                    if path is None:
                        path = []
                    if depth > max_depth:
                        return
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            p = path + [k]
                            yield p, v
                            if isinstance(v, (dict, list)):
                                yield from _walk(v, p, depth + 1, max_depth)
                    elif isinstance(obj, list):
                        for i, v in enumerate(obj):
                            p = path + [i]
                            yield p, v
                            if isinstance(v, (dict, list)):
                                yield from _walk(v, p, depth + 1, max_depth)

                def _as_str(v: Any) -> str:
                    if v is None:
                        return ""
                    try:
                        s = str(v).strip()
                    except Exception:
                        return ""
                    return s

                def _first_str_by_key_pred(obj: Any, pred) -> str:
                    for p, v in _walk(obj):
                        if not p:
                            continue
                        k = p[-1]
                        if not isinstance(k, str):
                            continue
                        # Avoid accidentally stringifying nested objects.
                        if isinstance(v, (dict, list)):
                            continue
                        if not pred(k, p):
                            continue
                        s = _as_str(v)
                        if s:
                            return s
                    return ""

                # Prefer top-level direct fields, but also handle nested schemas.
                search_obj = payload_data if payload_data else data

                # Session id (best-effort)
                self._session_id = _as_str(
                    payload_data.get("_id")
                    or payload_data.get("id")
                    or payload_data.get("session_id")
                    or payload_data.get("sessionId")
                    or ""
                )

                # Direct keys
                self._livekit_url = _as_str(payload_data.get("livekit_url") or payload_data.get("livekitUrl") or "")
                self._livekit_token = _as_str(payload_data.get("livekit_token") or payload_data.get("livekitToken") or "")
                self._livekit_room_name = _as_str(payload_data.get("livekit_room_name") or payload_data.get("livekitRoomName") or "")
                self._server_identity = _as_str(payload_data.get("livekit_server_identity") or payload_data.get("livekitServerIdentity") or "")

                # Nested: look for livekit url/token under any livekit-related path.
                if not self._livekit_url:
                    cand = _first_str_by_key_pred(
                        search_obj,
                        lambda k, p: (
                            ("livekit" in "/".join(str(x).lower() for x in p) or "livekit" in k.lower())
                            and "url" in k.lower()
                        ),
                    )
                    if cand.lower().startswith(("ws://", "wss://", "http://", "https://")):
                        self._livekit_url = cand

                if not self._livekit_url:
                    # Common pattern: livekit: { url: ..., ws_url: ... }
                    cand = _first_str_by_key_pred(
                        search_obj,
                        lambda k, p: (
                            "livekit" in "/".join(str(x).lower() for x in p)
                            and k.lower() in ("url", "ws_url", "wsurl", "wss_url", "wssurl", "server_url", "serverurl")
                        ),
                    )
                    if cand.lower().startswith(("ws://", "wss://", "http://", "https://")):
                        self._livekit_url = cand

                if not self._livekit_token:
                    cand = _first_str_by_key_pred(
                        search_obj,
                        lambda k, p: (
                            ("livekit" in "/".join(str(x).lower() for x in p) or "livekit" in k.lower())
                            and ("token" in k.lower() or k.lower() in ("jwt", "access_token", "accesstoken"))
                        ),
                    )
                    if len(cand) > 20:
                        self._livekit_token = cand

                if not self._livekit_room_name:
                    self._livekit_room_name = _first_str_by_key_pred(
                        search_obj,
                        lambda k, p: (
                            "livekit" in "/".join(str(x).lower() for x in p)
                            and ("room" in k.lower() and "name" in k.lower())
                        ),
                    )

                if not self._server_identity:
                    self._server_identity = _first_str_by_key_pred(
                        search_obj,
                        lambda k, p: (
                            "livekit" in "/".join(str(x).lower() for x in p)
                            and ("server" in k.lower() and "identity" in k.lower())
                        ),
                    )

                if not self._livekit_url or not self._livekit_token:
                    # Log only structural hints (no token values)
                    livekit_paths: list[str] = []
                    try:
                        for p, v in _walk(search_obj):
                            if not p:
                                continue
                            if any((isinstance(x, str) and "livekit" in x.lower()) for x in p):
                                livekit_paths.append("/".join(str(x) for x in p))
                            if len(livekit_paths) >= 25:
                                break
                    except Exception:
                        livekit_paths = []

                    top_keys = list(search_obj.keys()) if isinstance(search_obj, dict) else []
                    logger.warning(
                        f"Akool session create missing LiveKit details. code={code} msg={msg} "
                        f"top_keys={top_keys[:30]} livekit_paths={livekit_paths}"
                    )

                    raise RuntimeError("Akool session create did not return LiveKit connection details")

            async def _close_session(self):
                if not self._http or not self._session_id:
                    return
                url = f"{self._base_url}/api/open/v4/liveAvatar/session/close"
                try:
                    await self._http.post(url, json={"id": self._session_id})
                except Exception:
                    pass

            def _is_avatar_participant(self, participant: rtc.RemoteParticipant) -> bool:
                if not participant:
                    return False
                if self._server_identity:
                    return str(participant.identity or "") == self._server_identity
                # Fallback: first remote participant
                return True

            async def _process_audio_frames(self, stream: rtc.AudioStream):
                try:
                    async for frame_event in stream:
                        audio_frame = frame_event.frame

                        if not self._transport_ready or self._disabled:
                            continue

                        # LiveKit audio is typically PCM16.
                        audio_data = bytes(getattr(audio_frame, "data", b"") or b"")
                        if not audio_data:
                            continue

                        src_rate = int(getattr(audio_frame, "sample_rate", 0) or 0) or self._out_sample_rate
                        src_channels = int(getattr(audio_frame, "num_channels", 0) or 0) or 1

                        # Normalize to mono for Daily (and for our pipeline sample rate).
                        try:
                            if src_channels == 2:
                                audio_data = audioop.tomono(audio_data, 2, 0.5, 0.5)
                                src_channels = 1
                        except Exception:
                            # Best-effort; keep whatever we got.
                            src_channels = 1

                        # Resample to the pipeline / Daily output sample rate.
                        try:
                            if src_rate and src_rate != self._out_sample_rate:
                                audio_data, self._audio_ratecv_state = audioop.ratecv(
                                    audio_data,
                                    2,
                                    src_channels,
                                    src_rate,
                                    self._out_sample_rate,
                                    self._audio_ratecv_state,
                                )
                                src_rate = self._out_sample_rate
                        except Exception:
                            # If resampling fails, still try sending raw data.
                            pass

                        out = SpeechOutputAudioRawFrame(
                            audio=audio_data,
                            sample_rate=src_rate,
                            num_channels=src_channels,
                        )
                        if self._transport_destination is not None:
                            out.transport_destination = self._transport_destination
                        try:
                            out.pts = int(getattr(frame_event, "timestamp_us", 0) // 1000)
                        except Exception:
                            pass

                        await self.push_frame(out)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.warning(f"Akool audio stream ended: {e}")
                    try:
                        await self._disable_avatar(f"audio stream ended: {e}", exception=e)
                    except Exception:
                        pass

            async def _process_video_frames(self, stream: rtc.VideoStream):
                try:
                    async for frame_event in stream:
                        video_frame = frame_event.frame
                        try:
                            if getattr(video_frame, "type", None) != VideoBufferType.RGB24:
                                video_frame = video_frame.convert(VideoBufferType.RGB24)
                        except Exception:
                            pass

                        if not self._transport_ready or self._disabled:
                            continue

                        out = OutputImageRawFrame(
                            image=bytes(video_frame.data),
                            size=(int(video_frame.width), int(video_frame.height)),
                            format="RGB",
                        )
                        if self._transport_destination is not None:
                            out.transport_destination = self._transport_destination
                        try:
                            out.pts = int(frame_event.timestamp_us // 1000)
                        except Exception:
                            pass
                        await self.push_frame(out)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.warning(f"Akool video stream ended: {e}")
                    try:
                        await self._disable_avatar(f"video stream ended: {e}", exception=e)
                    except Exception:
                        pass

            async def _connect_livekit(self):
                if not self._livekit_url or not self._livekit_token:
                    raise RuntimeError("LiveKit config missing")

                self._room = rtc.Room()

                @self._room.on("track_subscribed")
                def on_track_subscribed(track: rtc.Track, publication: rtc.RemoteTrackPublication, participant: rtc.RemoteParticipant):
                    if not self._is_avatar_participant(participant):
                        return

                    try:
                        if track.kind == rtc.TrackKind.KIND_VIDEO and self._video_task is None:
                            stream = rtc.VideoStream(track)
                            try:
                                self._video_task = self.create_task(self._process_video_frames(stream), name="akool_video_stream")
                            except Exception:
                                self._video_task = asyncio.create_task(self._process_video_frames(stream))
                        elif track.kind == rtc.TrackKind.KIND_AUDIO and self._audio_task is None:
                            # NOTE: AudioStream ctor signature can vary; use positional to be safe.
                            stream = rtc.AudioStream(track)
                            try:
                                self._audio_task = self.create_task(self._process_audio_frames(stream), name="akool_audio_stream")
                            except Exception:
                                self._audio_task = asyncio.create_task(self._process_audio_frames(stream))
                    except Exception as e:
                        logger.debug(f"Akool track_subscribed handler error: {e}")

                await self._room.connect(
                    self._livekit_url,
                    self._livekit_token,
                    options=rtc.RoomOptions(auto_subscribe=True),
                )

                # Best-effort: start streams for already-subscribed tracks
                for p in (self._room.remote_participants or {}).values():
                    if not self._is_avatar_participant(p):
                        continue
                    for pub in p.track_publications.values():
                        try:
                            if pub.track is None:
                                continue
                            if pub.kind == rtc.TrackKind.KIND_VIDEO and self._video_task is None:
                                stream = rtc.VideoStream(pub.track)
                                try:
                                    self._video_task = self.create_task(self._process_video_frames(stream), name="akool_video_stream")
                                except Exception:
                                    self._video_task = asyncio.create_task(self._process_video_frames(stream))
                            if pub.kind == rtc.TrackKind.KIND_AUDIO and self._audio_task is None:
                                # NOTE: AudioStream ctor signature can vary; use positional to be safe.
                                stream = rtc.AudioStream(pub.track)
                                try:
                                    self._audio_task = self.create_task(self._process_audio_frames(stream), name="akool_audio_stream")
                                except Exception:
                                    self._audio_task = asyncio.create_task(self._process_audio_frames(stream))
                        except Exception:
                            continue

            async def _start_session(self):
                if self._room:
                    return
                await self._create_session()
                await self._connect_livekit()

            async def _stop_session(self):
                # Cancel stream tasks
                for t_name in ["_audio_task", "_video_task"]:
                    t = getattr(self, t_name)
                    if t is None:
                        continue
                    try:
                        if self._task_manager:
                            await self._task_manager.cancel_task(t)
                        else:
                            t.cancel()
                    except Exception:
                        pass
                    setattr(self, t_name, None)

                # Reset vision publishing state
                self._vision_source = None
                self._vision_track = None
                self._vision_width = 0
                self._vision_height = 0
                self._vision_last_sent_s = 0.0

                # Disconnect LiveKit
                if self._room:
                    try:
                        await self._room.disconnect()
                    except Exception:
                        pass
                    self._room = None

                # Close Akool session
                try:
                    await self._close_session()
                finally:
                    self._session_id = ""

            async def _ensure_vision_track(self, *, width: int, height: int) -> None:
                if not self._vision_enabled:
                    return
                if self._disabled:
                    return
                if not self._room:
                    return
                if self._vision_source is not None and self._vision_track is not None:
                    return

                width = int(width) if int(width) > 0 else 0
                height = int(height) if int(height) > 0 else 0
                if not width or not height:
                    return

                async with self._vision_lock:
                    if self._vision_source is not None and self._vision_track is not None:
                        return
                    if not self._room:
                        return

                    self._vision_width = width
                    self._vision_height = height

                    try:
                        self._vision_source = rtc.VideoSource(width, height)
                        self._vision_track = rtc.LocalVideoTrack.create_video_track("camera", self._vision_source)

                        # Track publish options vary by livekit SDK version; keep this best-effort.
                        opts = None
                        try:
                            TrackPublishOptions = getattr(rtc, "TrackPublishOptions", None)
                            TrackSource = getattr(rtc, "TrackSource", None)
                            if TrackPublishOptions is not None:
                                if TrackSource is not None and hasattr(TrackSource, "SOURCE_CAMERA"):
                                    opts = TrackPublishOptions(source=TrackSource.SOURCE_CAMERA)
                                else:
                                    opts = TrackPublishOptions()
                        except Exception:
                            opts = None

                        try:
                            if opts is None:
                                await self._room.local_participant.publish_track(self._vision_track)
                            else:
                                await self._room.local_participant.publish_track(self._vision_track, opts)
                        except Exception:
                            # Older SDKs may require the options arg.
                            await self._room.local_participant.publish_track(self._vision_track, opts)  # type: ignore

                        logger.info(f"Akool Vision Sense enabled: publishing user camera to LiveKit ({width}x{height} @ {self._vision_fps}fps)")
                    except Exception as e:
                        # Don't kill the whole session if vision publishing fails.
                        self._vision_source = None
                        self._vision_track = None
                        logger.warning(f"Akool Vision Sense publish failed (continuing without vision): {e}")

            async def ingest_user_image(self, frame: UserImageRawFrame) -> None:
                """Best-effort: publish Daily participant camera frames into Akool's LiveKit room."""
                if not self._vision_enabled:
                    return
                if self._disabled:
                    return
                if not self._room:
                    return

                try:
                    w, h = frame.size
                except Exception:
                    return

                # Throttle frames to configured FPS.
                try:
                    now = asyncio.get_running_loop().time()
                except Exception:
                    now = 0.0

                min_interval = 1.0 / float(self._vision_fps or 1)
                if self._vision_last_sent_s and (now - self._vision_last_sent_s) < min_interval:
                    return
                self._vision_last_sent_s = now

                fmt = str(getattr(frame, "format", "") or "").upper()
                if fmt not in ("RGB", "RGB24"):
                    return

                img = getattr(frame, "image", b"") or b""
                if not img:
                    return

                expected = int(w) * int(h) * 3
                if expected <= 0:
                    return
                if len(img) < expected:
                    return
                if len(img) != expected:
                    img = bytes(img[:expected])

                await self._ensure_vision_track(width=int(w), height=int(h))
                if not self._vision_source:
                    return

                try:
                    vf = rtc.VideoFrame(int(w), int(h), VideoBufferType.RGB24, img)
                    self._vision_source.capture_frame(vf)
                except Exception as e:
                    logger.debug(f"Akool Vision Sense capture_frame failed: {e}")

            async def _send_stream_message(self, obj: dict[str, Any]):
                if not self._room:
                    return
                data = json.dumps(obj).encode("utf-8")
                try:
                    if self._server_identity:
                        await self._room.local_participant.publish_data(
                            data,
                            reliable=True,
                            destination_identities=[self._server_identity],
                        )
                    else:
                        await self._room.local_participant.publish_data(data, reliable=True)
                except Exception as e:
                    logger.debug(f"Akool publish_data failed: {e}")

            async def _send_text(self, text: str):
                """Send a chat message to the Akool avatar over the WebRTC data channel.

                Akool Streaming Avatar expects the stream message schema:
                  - type: "chat"
                  - idx/fin for chunking
                """
                text = str(text or "").strip()
                if not text:
                    return

                async with self._send_lock:
                    mid = f"msg-{uuid.uuid4().hex}"
                    self._current_mid = mid
                    payload = {
                        "v": 2,
                        "type": "chat",
                        "mid": mid,
                        "idx": 0,
                        "fin": True,
                        "pld": {"text": text},
                    }
                    await self._send_stream_message(payload)

            async def _interrupt(self):
                # Interrupt any currently scheduled avatar speech.
                async with self._send_lock:
                    mid = f"msg-{uuid.uuid4().hex}"
                    payload = {
                        "v": 2,
                        "type": "command",
                        "mid": mid,
                        "pld": {"cmd": "interrupt"},
                    }
                    await self._send_stream_message(payload)

            def _split_flushable(self, s: str) -> tuple[str, str]:
                # Flush on sentence-ish boundaries.
                if not s:
                    return "", ""
                last = max(s.rfind("."), s.rfind("!"), s.rfind("?"), s.rfind("\n"))
                if last < 0:
                    # Also flush very long buffers to avoid huge single messages.
                    if len(s) > 400:
                        return s[:400], s[400:]
                    return "", s
                return s[: last + 1], s[last + 1 :]

            async def _disable_avatar(self, reason: str, exception: Exception | None = None):
                async with self._shutdown_lock:
                    if self._disabled:
                        return
                    self._disabled = True
                    self._disabled_reason = str(reason or "").strip()

                    msg = "Akool avatar disabled for this meeting" + (
                        f": {self._disabled_reason}" if self._disabled_reason else ""
                    )
                    if exception:
                        msg += f" ({exception})"
                    logger.warning(msg)

                    async def _shutdown():
                        try:
                            await self._stop_session()
                        except Exception:
                            pass

                    if not self._shutdown_task:
                        try:
                            self._shutdown_task = self.create_task(_shutdown(), name="akool_shutdown")
                        except Exception:
                            try:
                                self._shutdown_task = asyncio.create_task(_shutdown())
                            except Exception:
                                pass

            async def process_frame(self, frame: Frame, direction: FrameDirection):
                await super().process_frame(frame, direction)

                if isinstance(frame, StartFrame):
                    # Some transports/versions may not emit OutputTransportReadyFrame in a way
                    # that reaches this processor. We still want to forward avatar audio/video
                    # once the pipeline starts.
                    self._transport_ready = True
                    try:
                        self._transport_destination = getattr(frame, "transport_destination", None)
                    except Exception:
                        self._transport_destination = None

                    if not self._disabled:
                        try:
                            await self._start_session()
                        except Exception as e:
                            await self._disable_avatar(f"start failed: {e}", exception=e)
                    await self.push_frame(frame, direction)
                    return

                if isinstance(frame, OutputTransportReadyFrame):
                    self._transport_ready = True
                    try:
                        if self._transport_destination is None:
                            self._transport_destination = getattr(frame, "transport_destination", None)
                    except Exception:
                        pass
                    await self.push_frame(frame, direction)
                    return

                if isinstance(frame, (PipecatEndFrame, CancelFrame)):
                    try:
                        await self._stop_session()
                    except Exception:
                        pass
                    await self.push_frame(frame, direction)
                    return

                if self._disabled:
                    await self.push_frame(frame, direction)
                    return

                if isinstance(frame, UserImageRawFrame):
                    # Best-effort: forward participant camera frames into Akool for Vision Sense.
                    try:
                        await self.ingest_user_image(frame)
                    except Exception:
                        pass
                    await self.push_frame(frame, direction)
                    return

                if isinstance(frame, (UserStartedSpeakingFrame, InterruptionFrame)):
                    # Best-effort: stop current avatar speech when the user interrupts.
                    try:
                        await self._interrupt()
                    except Exception:
                        pass
                    await self.push_frame(frame, direction)
                    return

                if isinstance(frame, PipecatTTSTextFrame):
                    # Greeting / direct text frames
                    try:
                        await self._send_text(str(frame.text or ""))
                    except Exception as e:
                        await self._disable_avatar(f"send_text failed: {e}", exception=e)
                    await self.push_frame(frame, direction)
                    return

                if isinstance(frame, LLMTextFrame):
                    # Buffer streaming LLM tokens into sentences.
                    self._pending_text += str(frame.text or "")
                    flush, rest = self._split_flushable(self._pending_text)
                    self._pending_text = rest
                    if flush.strip():
                        try:
                            await self._send_text(flush)
                        except Exception as e:
                            await self._disable_avatar(f"send_text failed: {e}", exception=e)
                    await self.push_frame(frame, direction)
                    return

                if isinstance(frame, LLMFullResponseEndFrame):
                    # Flush any remaining buffered text.
                    if self._pending_text.strip():
                        try:
                            await self._send_text(self._pending_text)
                        except Exception as e:
                            await self._disable_avatar(f"send_text failed: {e}", exception=e)
                    self._pending_text = ""
                    await self.push_frame(frame, direction)
                    return

                await self.push_frame(frame, direction)

        akool_service = AkoolVideoService(
            api_key=akool_api_key,
            base_url=akool_base_url,
            avatar_id=akool_avatar_id,
            voice_id=akool_voice_id,
            background_id=akool_background_id,
            mode_type=akool_mode_type,
            duration_seconds=akool_duration,
            out_sample_rate=sample_rate,
            vision_enabled=akool_vision_enabled,
            vision_fps=akool_vision_fps,
        )

    # IMPORTANT: assistant context aggregator consumes TextFrames (it aggregates them and does
    # not forward). If it sits *before* TTS, the bot will generate text but you won't hear audio.
    # So we place it after TTS and before the output transport.

    ctx_user = ctx.user()
    ctx_assistant = ctx.assistant()

    def _mono_time_s() -> float:
        try:
            return asyncio.get_running_loop().time()
        except Exception:
            return 0.0

    # Optional: keep a "latest camera frame" snapshot and attach it to the user's next LLM turn.
    vision_state: dict[str, Any] | None = None
    if is_video_meeting and video_avatar_provider == "akool" and akool_vision_llm_enabled:
        vision_state = {"format": "", "size": (0, 0), "image": b"", "ts": 0.0}

        import types

        def _should_attach_vision_to_text(text: str) -> bool:
            mode = str(akool_vision_llm_attach_mode or "always").strip().lower()
            if mode == "never":
                return False
            if mode == "always":
                return True

            # auto: only attach vision when the user likely needs it.
            t = str(text or "").strip().lower()
            if not t:
                return False

            # Simple keyword heuristic (fast + avoids extra model calls).
            keywords = (
                "see",
                "look",
                "show",
                "camera",
                "image",
                "photo",
                "picture",
                "screen",
                "read",
                "what is this",
                "what's this",
                "who is",
                "what am i",
                "wearing",
                "holding",
                "color",
                "colour",
                "shirt",
                "hat",
                "glasses",
                "sign",
                "logo",
                "text",
            )
            return any(k in t for k in keywords)

        async def _handle_aggregation_with_vision(self, aggregation: str):
            text = str(aggregation or "").strip()
            if not text:
                return

            # If not needed, keep this as a plain text turn (fast path).
            if not _should_attach_vision_to_text(text):
                self._context.add_message({"role": self.role, "content": text})
                return

            snap = vision_state or {}
            img = snap.get("image") or b""
            if img:
                now = _mono_time_s()
                ts = float(snap.get("ts") or 0.0)
                if akool_vision_llm_max_age_s <= 0 or (now - ts) <= akool_vision_llm_max_age_s:
                    try:
                        fmt = str(snap.get("format") or "RGB").strip() or "RGB"
                        size = tuple(snap.get("size") or (0, 0))

                        # Convert to a smaller JPEG in a worker thread to avoid blocking the event loop.
                        def _encode_jpeg_b64() -> tuple[str, tuple[int, int]]:
                            import base64
                            import io

                            from PIL import Image

                            im = Image.frombytes(fmt, size, img)
                            if akool_vision_llm_max_dim and max(im.size) > int(akool_vision_llm_max_dim):
                                im.thumbnail((int(akool_vision_llm_max_dim), int(akool_vision_llm_max_dim)))

                            buf = io.BytesIO()
                            im.save(
                                buf,
                                format="JPEG",
                                quality=int(akool_vision_llm_jpeg_quality),
                                optimize=True,
                            )
                            b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
                            return b64, (int(im.size[0]), int(im.size[1]))

                        b64, resized = await asyncio.to_thread(_encode_jpeg_b64)
                        content: list[dict[str, Any]] = [
                            {"type": "text", "text": text},
                            {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64}"}},
                        ]
                        self._context.add_message({"role": "user", "content": content})
                        logger.debug(f"Attached vision frame to LLM ({resized[0]}x{resized[1]})")
                        return
                    except Exception as e:
                        logger.debug(f"Vision frame attach failed (falling back to text): {e}")

            self._context.add_message({"role": self.role, "content": text})

        ctx_user.handle_aggregation = types.MethodType(_handle_aggregation_with_vision, ctx_user)
        logger.info(
            "Akool assistant vision enabled: attaching participant camera frames to LLM input (requires a vision-capable model)"
        )

    # For Akool Vision Sense, capture participant camera frames and forward to Akool.
    akool_vision_bridge = None
    if is_video_meeting and video_avatar_provider == "akool" and akool_service and akool_vision_capture_enabled:

        class AkoolVisionBridge(FrameProcessor):
            def __init__(self, *, akool: Any, vision_state: Optional[dict[str, Any]] = None):
                super().__init__()
                self._akool = akool
                self._vision_state = vision_state

            async def process_frame(self, frame, direction: FrameDirection):
                await super().process_frame(frame, direction)

                if direction is FrameDirection.DOWNSTREAM and isinstance(frame, UserImageRawFrame):
                    # Best-effort: store for the LLM.
                    if self._vision_state is not None:
                        try:
                            self._vision_state["format"] = str(getattr(frame, "format", "") or "RGB").strip() or "RGB"
                            self._vision_state["size"] = tuple(getattr(frame, "size", (0, 0)) or (0, 0))
                            self._vision_state["image"] = bytes(getattr(frame, "image", b"") or b"")
                            self._vision_state["ts"] = _mono_time_s()
                        except Exception:
                            pass

                    # Best-effort: forward to Akool LiveKit (no-op if Akool vision publishing is disabled).
                    try:
                        await self._akool.ingest_user_image(frame)
                    except Exception:
                        pass

                    # Drop the raw frame to avoid sending large video frames through the rest of the pipeline.
                    return

                await self.push_frame(frame, direction)

        akool_vision_bridge = AkoolVisionBridge(akool=akool_service, vision_state=vision_state)

    steps = [
        transport.input(),
    ]
    if akool_vision_bridge:
        steps.append(akool_vision_bridge)
    steps.extend([
        stt,
        ctx_user,
        llm,
    ])
    if tts:
        steps.append(tts)
    if bg_mixer:
        steps.append(bg_mixer)
    if heygen_service:
        steps.append(heygen_service)
    if akool_service:
        steps.append(akool_service)
    steps.extend([
        ctx_assistant,
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

    greeted = False
    video_capture_started = False

    @transport.event_handler("on_first_participant_joined")
    async def on_first_participant_joined(_transport, _participant):
        nonlocal greeted
        nonlocal video_capture_started

        # Optional greeting
        if greeting and not greeted:
            greeted = True
            try:
                context.add_message({"role": "assistant", "content": greeting})
            except Exception:
                pass
            await task.queue_frames([TTSTextFrame(greeting, aggregated_by=AggregationType.SENTENCE)])

        # Akool Vision Sense: capture participant camera and forward to Akool LiveKit.
        if (
            not video_capture_started
            and is_video_meeting
            and video_avatar_provider == "akool"
            and akool_vision_capture_enabled
        ):
            pid = ""
            try:
                if isinstance(_participant, dict):
                    pid = str(
                        _participant.get("id")
                        or _participant.get("participant_id")
                        or _participant.get("participantId")
                        or ""
                    ).strip()
                else:
                    pid = str(getattr(_participant, "id", "") or getattr(_participant, "participant_id", "") or "").strip()
            except Exception:
                pid = ""

            if pid:
                video_capture_started = True
                try:
                    await transport.capture_participant_video(
                        pid,
                        framerate=akool_vision_fps,
                        video_source="camera",
                        color_format="RGB",
                    )
                    logger.info(f"Akool Vision Sense: capturing participant camera (id={pid}) at {akool_vision_fps}fps")
                except Exception as e:
                    logger.warning(f"Akool Vision Sense: failed to capture participant camera (id={pid}): {e}")

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
