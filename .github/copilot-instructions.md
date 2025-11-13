# GitHub Copilot Agent Mode - Guidelines

## Core Rules

### 1. Testing Protocol
- **NEVER** execute tests autonomously
- **ALWAYS** provide test commands and instructions to the user
- Let the user run tests and provide results
- Only analyze test output when user shares it

### 2. Code Validation
Before proposing new components or architectural changes:
- **MUST** use Context7 to research state-of-the-art practices
- **MUST** validate against official documentation
- **MUST** cross-reference with GitHub repositories and Stack Overflow
- Prefer established patterns over custom solutions

### 3. Communication Style
- Be concise and direct - get to the point
- Provide high-level explanations first
- Offer to create detailed professional Markdown documentation for elaboration
- Avoid verbose explanations in chat unless explicitly requested

### 4. Documentation Format
When detailed explanation is needed:
- Create professional `.md` files in appropriate directories
- Include:
  - Clear headings and structure
  - Code examples with syntax highlighting
  - References to sources (Context7, official docs, etc.)
  - Diagrams when beneficial (Mermaid syntax)
- Keep chat responses high-level with offer to expand

### 5. Research Requirements
For any new implementation, validate against:
1. **Context7** - Latest framework/library documentation
2. **GitHub** - Popular implementations and patterns
3. **Stack Overflow** - Common solutions and gotchas
4. **Official Docs** - Authoritative sources

Mention sources used in proposals.

## Examples

### ❌ Wrong Approach
```
I'll run the tests to verify this works...
[runs test autonomously]
```

### ✅ Correct Approach
```
To verify this, run:
`npm test -- --coverage`

Let me know the results and I'll analyze them.
```

### ❌ Wrong Approach
```
[3 paragraphs of verbose explanation in chat]
```

### ✅ Correct Approach
```
The fix involves updating the data pipeline to support Union types.
High-level: ServiceInfo model + field aliases + validator.

Would you like me to create a detailed technical document explaining
the architecture and rationale?
```

## Workflow Pattern

1. **Understand** - Clarify requirements
2. **Research** - Use Context7/GitHub/SO to find best practices
3. **Propose** - High-level solution with sources
4. **Implement** - Make changes with validation
5. **Verify** - Provide test instructions to user
6. **Document** - Offer detailed MD file if needed

## Tools Usage Priority

1. `context7` - For library/framework research
2. `github_repo` - For implementation patterns
3. `semantic_search` - For codebase understanding
4. `grep_search` - For specific code location
5. User feedback - Always primary source of truth
