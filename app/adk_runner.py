from __future__ import annotations

import asyncio
import uuid
from typing import Any

from google.adk.runners import (
    InMemoryRunner,
)
from google.genai import types


async def _run_agent_async(
    agent,
    prompt: str,
    app_name: str,
) -> tuple[
    str,
    list[dict[str, Any]],
]:

    runner = InMemoryRunner(
        agent=agent,
        app_name=app_name,
    )

    user_id = "securepatch-user"

    session = (
        await runner.session_service.create_session(
            app_name=app_name,
            user_id=user_id,
            session_id=str(
                uuid.uuid4()
            ),
        )
    )

    message = types.Content(
        role="user",
        parts=[
            types.Part.from_text(
                text=prompt
            )
        ],
    )

    final_text = ""

    trace = []

    async for event in runner.run_async(
        user_id=user_id,
        session_id=session.id,
        new_message=message,
    ):

        if (
            not event.content
            or not event.content.parts
        ):
            continue

        for part in event.content.parts:

            if part.text:
                final_text = part.text

            if part.function_call:

                trace.append(
                    {
                        "type": "tool_call",
                        "tool": (
                            part.function_call.name
                        ),
                        "args": dict(
                            part.function_call.args
                            or {}
                        ),
                    }
                )

            if part.function_response:

                trace.append(
                    {
                        "type": "tool_result",
                        "tool": (
                            part.function_response.name
                        ),
                        "response": (
                            part.function_response.response
                        ),
                    }
                )

    return (
        final_text,
        trace,
    )


def run_agent(
    agent,
    prompt: str,
    app_name: str,
) -> tuple[
    str,
    list[dict[str, Any]],
]:

    return asyncio.run(
        _run_agent_async(
            agent=agent,
            prompt=prompt,
            app_name=app_name,
        )
    )
    