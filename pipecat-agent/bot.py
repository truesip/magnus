import inspect
import json
import os
from typing import Any, Optional

import httpx
from deepgram.clients.listen.v1.websocket.options import LiveOptions

from pipecat.audio.vad.silero import SileroVADAnalyzer
from pipecat.frames.frames import AggregationType, TTSTextFrame
from pipecat.pipeline.pipeline import Pipeline
from pipecat.pipeline.runner import PipelineRunner
from pipecat.pipeline.task import PipelineParams, PipelineTask
from pipecat.processors.aggregators.openai_llm_context import OpenAILLMContext
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

    # Portal integration (used for emailing templated documents)
    portal_base_url = _env("PORTAL_BASE_URL", "").strip().rstrip("/")
    portal_token = _env("PORTAL_AGENT_ACTION_TOKEN", "").strip()
    tools = []

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

    # Extend the user-provided prompt with minimal tool guidance.
    prompt = base_prompt
    if tools:
        prompt += (
            "\n\nYou can email the caller a document when requested. "
            "Collect their email and any details needed for the template placeholders, "
            "then call the send_document tool with to_email and variables. "
            "After the tool returns, confirm whether the email was sent."
        )

    room_url = getattr(session_args, "room_url", None) or getattr(session_args, "roomUrl", None) or ""
    token = getattr(session_args, "token", None) or getattr(session_args, "room_token", None) or ""
    if not room_url:
        raise RuntimeError(f"Missing room_url in session args: {type(session_args)}")

    sample_rate = _parse_int("AUDIO_SAMPLE_RATE", 16000)

    body = getattr(session_args, "body", None)
    dialin_settings = _extract_dialin_settings(body)
    daily_api_key, daily_api_url = _extract_daily_api(body)

    daily_params = DailyParams(
        api_key=daily_api_key or "",
        api_url=daily_api_url or "https://api.daily.co/v1",
        dialin_settings=dialin_settings,
        audio_in_enabled=True,
        audio_out_enabled=True,
        audio_in_sample_rate=sample_rate,
        audio_out_sample_rate=sample_rate,
        # NOTE: vad_enabled is deprecated in Pipecat 0.0.98; supplying a vad_analyzer is sufficient.
        vad_analyzer=SileroVADAnalyzer(),
    )

    transport = DailyTransport(
        room_url=str(room_url),
        token=str(token) if token else None,
        bot_name=_env("BOT_NAME", "TalkUSA AI Agent").strip() or "TalkUSA AI Agent",
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
    if tools:
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

    ctx = llm.create_context_aggregator(context)

    # IMPORTANT: assistant context aggregator consumes TextFrames (it aggregates them and does
    # not forward). If it sits *before* TTS, the bot will generate text but you won't hear audio.
    # So we place it after TTS and before the output transport.
    pipeline = Pipeline(
        [
            transport.input(),
            stt,
            ctx.user(),
            llm,
            tts,
            ctx.assistant(),
            transport.output(),
        ]
    )

    task = PipelineTask(
        pipeline,
        params=PipelineParams(
            allow_interruptions=True,
            audio_in_sample_rate=sample_rate,
            audio_out_sample_rate=sample_rate,
        ),
    )

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
    await runner.run(task)
