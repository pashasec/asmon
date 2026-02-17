"""
ai/analysis.py — Optional AI-assisted attack surface analysis.

Design constraints (non-negotiable):
  1. AI output is ALWAYS in a separate envelope (AIAnalysis model).
     It is never mixed with or presented as raw data.
  2. The prompt is logged verbatim so you can see exactly what was sent.
  3. The AI is asked to flag risks, not invent them. The prompt explicitly
     instructs the model to ground observations in the provided data.
  4. If the AI call fails, the rest of the tool continues normally.
     AI is advisory. Never a hard dependency.

Supported providers:
  - openai  (default: gpt-4o-mini)
  - anthropic (haiku-3)

Set ASMON_AI_PROVIDER and ASMON_AI_API_KEY in env, or pass at runtime.
"""

import logging
from asmon.models import SurfaceDiff, AIAnalysis
from asmon import config

logger = logging.getLogger("asmon.ai")
# Note: openai and anthropic are imported lazily in _call_openai and _call_anthropic


# Deliberately structured: data first, instructions second.
DIFF_ANALYSIS_PROMPT = """You are analysing an attack surface change report.
Below is a structured diff showing what changed between two snapshots of an organisation's external exposure.

--- BEGIN DIFF DATA ---
{diff_text}
--- END DIFF DATA ---

Based ONLY on the data above, provide:

1. A 3-5 sentence plain-English summary of the most significant changes.
2. A list of risk flags, if any. Each flag should reference a specific IP, port, or service from the data.
   Only flag things that are actually present in the diff. Do not speculate.

Risk categories to watch for (only flag if evidence exists in the data):
  - New ports on previously known hosts
  - Services that appear to be admin panels or management interfaces
  - Services with known CVEs
  - SSL certificates that are expiring or have changed unexpectedly
  - Hosts that changed organisation or ASN (possible infrastructure handoff)
  - Unauthenticated services (Redis, MongoDB, Elasticsearch on default ports)

Format your response as:
SUMMARY:
<your summary>

RISK FLAGS:
- <flag 1>
- <flag 2>
(or "None identified" if the diff is clean)
"""


def analyse_diff(diff: SurfaceDiff, api_key: str | None = None,
                 provider: str | None = None, model: str | None = None) -> AIAnalysis:
    """
    Run AI analysis on a SurfaceDiff.
    Returns AIAnalysis. Never raises on AI failure — returns error in envelope.
    """
    provider = provider or config.AI_PROVIDER
    model   = model   or config.AI_MODEL
    api_key = api_key or config.AI_API_KEY

    if not api_key:
        raise ValueError("AI analysis requires ASMON_AI_API_KEY env var or --ai-key flag.")

    from asmon.output import render_diff
    diff_text = render_diff(diff, fmt="text")
    prompt = DIFF_ANALYSIS_PROMPT.format(diff_text=diff_text)

    logger.info("Sending diff to %s/%s for analysis.", provider, model)

    try:
        raw_response = _call_llm(provider, model, api_key, prompt)
    except Exception as exc:
        logger.warning("AI analysis failed: %s", exc)
        return AIAnalysis(
            provider=provider, model=model,
            raw_prompt=prompt,
            summary=f"[AI analysis failed: {exc}]",
            flags=[],
        )

    summary, flags = _parse_response(raw_response)
    return AIAnalysis(
        provider=provider, model=model,
        raw_prompt=prompt, summary=summary, flags=flags,
    )


def _call_llm(provider: str, model: str, api_key: str, prompt: str) -> str:
    if provider == "openai":
        return _call_openai(model, api_key, prompt)
    elif provider == "anthropic":
        return _call_anthropic(model, api_key, prompt)
    raise ValueError(f"Unsupported AI provider: {provider!r}")


def _call_openai(model: str, api_key: str, prompt: str) -> str:
    try:
        from openai import OpenAI
    except ImportError as e:
        raise ImportError("openai package not installed. Install with: pip install openai") from e
    client = OpenAI(api_key=api_key)
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1024, temperature=0.1,
    )
    return resp.choices[0].message.content or ""


def _call_anthropic(model: str, api_key: str, prompt: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=api_key)
    resp = client.messages.create(
        model=model, max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text if resp.content else ""


def _parse_response(text: str) -> tuple[str, list[str]]:
    """Extract SUMMARY and RISK FLAGS from LLM output. Graceful on bad format."""
    sections = text.split("RISK FLAGS:")
    if len(sections) != 2:
        return text.strip(), []

    summary_raw, flags_raw = sections
    summary = summary_raw.split("SUMMARY:", 1)[-1].strip()
    flags = [
        line.strip()[2:]
        for line in flags_raw.strip().splitlines()
        if line.strip().startswith("- ") and "None identified" not in line
    ]
    return summary, flags


def render_analysis(analysis: AIAnalysis) -> str:
    """Format AIAnalysis for terminal output."""
    box_width = 70
    lines = [
        "",
        "╔" + "═" * box_width + "╗",
        "║  AI ANALYSIS  (advisory only — not authoritative)" + " " * 18 + "║",
        f"║  Provider: {analysis.provider:<10} Model: {analysis.model:<40}║",
        "╚" + "═" * box_width + "╝",
        "",
        "  SUMMARY:",
    ]
    # Word-wrap at 66 chars
    for chunk in _wrap(analysis.summary, 66):
        lines.append(f"    {chunk}")
    lines.append("")

    if analysis.flags:
        lines.append("  RISK FLAGS:")
        for flag in analysis.flags:
            lines.append(f"    ⚠  {flag}")
    else:
        lines.append("  RISK FLAGS: None identified.")
    lines.append("")
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    """Simple word-wrap."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}" if current else word
    if current:
        lines.append(current)
    return lines
