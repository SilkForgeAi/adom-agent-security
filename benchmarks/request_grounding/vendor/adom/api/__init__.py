"""Lazy public exports: security primitives do not load optional ML/UI packages."""
from importlib import import_module

_EXPORTS = {'AIClient': ('.clients', 'AIClient'), 'APIResponse': ('.clients', 'APIResponse'), 'OpenAIClient': ('.clients', 'OpenAIClient'), 'AnthropicClient': ('.clients', 'AnthropicClient'), 'GoogleClient': ('.clients', 'GoogleClient'), 'APIManager': ('.clients', 'APIManager'), 'TestExecutor': ('.test_executor', 'TestExecutor')}
__all__ = ['AIClient', 'APIResponse', 'OpenAIClient', 'AnthropicClient', 'GoogleClient', 'APIManager', 'TestExecutor']

def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(name)
    module, attribute = _EXPORTS[name]
    value = getattr(import_module(module, __name__), attribute)
    globals()[name] = value
    return value
