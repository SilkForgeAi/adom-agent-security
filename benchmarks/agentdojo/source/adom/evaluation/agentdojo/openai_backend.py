"""Explicit request parameters, leaving the installed benchmark SDK untouched."""
from openai import NOT_GIVEN
import json
from agentdojo.functions_runtime import FunctionCall
from agentdojo.types import ChatAssistantMessage, text_content_block_from_string, get_text_content_as_str
from agentdojo.agent_pipeline.llms.openai_llm import (
    OpenAILLM, _message_to_openai, _function_to_openai, _openai_to_assistant_message,
)
from agentdojo.functions_runtime import EmptyEnv


class ExplicitOpenAILLM(OpenAILLM):
    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args=None):
        if self.model.startswith("gpt-5.4-mini"):
            return self.responses_query(query, runtime, env, messages, extra_args)
        tools = [_function_to_openai(t) for t in runtime.functions.values()]
        request = dict(model=self.model,
                       messages=[_message_to_openai(m, self.model) for m in messages],
                       tools=tools or NOT_GIVEN, tool_choice="auto" if tools else NOT_GIVEN,
                       max_completion_tokens=8192)
        if self.model == "gpt-4o-2024-05-13":
            request.pop("max_completion_tokens")
            request["max_tokens"] = 4096
        if self.model.startswith("gpt-5.4-mini"):
            request["reasoning_effort"] = "medium"
        else:
            request["temperature"] = 0 if self.temperature is None else self.temperature
        if (extra_args or {}).get('publication_json'):
            if tools:raise RuntimeError('publication formatting cannot have tool authority')
            request['response_format'] = {'type': 'json_object'}
        completion = self.client.chat.completions.create(**request)
        if completion.choices[0].finish_reason == "length":
            raise RuntimeError("model response truncated; episode inconclusive")
        return query, runtime, env, [*messages, _openai_to_assistant_message(completion.choices[0].message)], extra_args or {}

    def responses_query(self, query, runtime, env, messages, extra_args):
        fresh_episode = bool(messages and messages[-1]["role"] == "user" and not any(m["role"] == "tool" for m in messages))
        if not hasattr(self, "_response_history") or fresh_episode:
            self._response_history = []
            self._seen_messages = 0
            self.responses_audit = []
        if len(messages) < self._seen_messages:
            raise RuntimeError("response conversation reused across episodes")
        for m in messages[self._seen_messages:]:
            content = get_text_content_as_str(m.get("content") or [])
            if m["role"] == "tool":
                self._response_history.append(dict(type="function_call_output", call_id=m["tool_call_id"], output=m.get("error") or content))
            elif m["role"] in {"user", "system", "assistant"}:
                self._response_history.append(dict(role=m["role"], content=content))
            else:
                raise RuntimeError("unsupported response input role")
        tools = [dict(type="function", name=t.name, description=t.description,
                      parameters=t.parameters.model_json_schema(), strict=False) for t in runtime.functions.values()]
        response = self.client.responses.create(model=self.model, input=self._response_history,
                                                tools=tools, store=False, include=["reasoning.encrypted_content"],
                                                reasoning={"effort":"medium"}, max_output_tokens=8192)
        if response.status != "completed":
            raise RuntimeError("response incomplete; episode inconclusive")
        items = [item.model_dump(exclude_none=True) for item in response.output]
        # Preserve provider reasoning items between tool steps, without reading
        # or attempting to decode reasoning. Conversation remains episode-local.
        self._response_history.extend(items)
        self.responses_audit.append(dict(id=response.id, status=response.status, usage=response.usage.model_dump() if response.usage else None))
        calls = [FunctionCall(function=item.name,args=json.loads(item.arguments),id=item.call_id)
                 for item in response.output if item.type == "function_call"]
        answer = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string(response.output_text)] if response.output_text else None,
                                      tool_calls=calls or None)
        self._seen_messages = len(messages) + 1
        return query, runtime, env, [*messages, answer], extra_args or {}
