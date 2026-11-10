# 📌 Instruções Passo a Passo: Ativação do Repositório no Zenodo (PQC)

Para registrar oficialmente o repositório `bruno-olivaes/pqc-crypto-agility-benchmark` e emitir um DOI citação citable para o software de auditoria de criptografia pós-quântica e dados de benchmark, siga os passos abaixo:

---

### Passo 1: Acesse as Configurações do GitHub no Zenodo
1. Acesse: **[https://zenodo.org/account/settings/github/](https://zenodo.org/account/settings/github/)**
2. Se não estiver conectado, faça login com sua conta do GitHub (`bruno-olivaes`).

---

### Passo 2: Sincronizar e Ativar o Repositório
1. Na lista de repositórios, clique no botão **"Sync now"** no canto superior direito.
2. Localize na lista o repositório:
   ```
   bruno-olivaes/pqc-crypto-agility-benchmark
   ```
3. Mude a chavinha (toggle) ao lado do repositório de **OFF** para **ON** (Verde).

---

### Passo 3: Criar a Release Oficial no GitHub
Assim que o toggle estiver ativo no Zenodo, crie uma Release no GitHub para disparar o arquivamento automático e geração do DOI:

Execute no terminal:
```bash
cd C:\Users\bruno\projects\pqc-crypto-agility-benchmark
gh release create v1.0.0 --title "v1.0.0 - The Network Cost of Post-Quantum Cryptography: TCP Fragmentation in TLS 1.3 Handshakes" --notes "First official scientific release including ML-KEM-768 vs RSA benchmarks, TLS 1.3 socket MTU audit, and LaTeX manuscript."
```

O Zenodo detectará a nova release em instantes e atribuirá um DOI persistente (ex.: `10.5281/zenodo.XXXXXXX`).

---

### Passo 4: Adicionar o Badge ao README.md
Após a emissão do DOI pelo Zenodo, inclua o badge no início do `README.md`:
```markdown
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.XXXXXXX.svg)](https://doi.org/10.5281/zenodo.XXXXXXX)
```
