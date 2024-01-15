import re

# Carregue o arquivo rules.toml
with open("rules.toml", "r") as f:
    texto = f.read()
    rule_ids = re.findall(r'\[\[rules\]\]\s*id\s*=\s*"([^"]*)"', texto)
    with open('validator.py', 'r') as file:
        validator_content = file.read()
    markdown_lines = []
    for rule_id in rule_ids:
        if rule_id in validator_content:
            markdown_lines.append(f'- [X] {rule_id}')
        else:
            markdown_lines.append(f'- [ ] {rule_id}')


    with open('README.md', 'r', encoding="utf-8") as file:
        readme_content = file.read()

    # Divida o conteúdo do arquivo README.md na seção "## keys"
    parts = re.split(r'(## keys)', readme_content, flags=re.IGNORECASE)
    new_readme_content = parts[0] + '## keys\n' + '\n'.join(markdown_lines)
    with open('README.md', 'w', encoding="utf-8") as file:
        file.write(new_readme_content)