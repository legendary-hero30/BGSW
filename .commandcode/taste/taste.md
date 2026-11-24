# Taste

- Prefers real implementations over mocks and fallbacks: when a real LLM provider is available, drop scripted/mock models (e.g. `scripted-v1`) and mock agent responses entirely rather than keeping them as a default path. Confidence: 0.7
- Prefers explainer content (config snippets, .gitignore blocks, command walkthroughs) delivered directly in the chat reply rather than created as new files in the repo. Confidence: 0.65
