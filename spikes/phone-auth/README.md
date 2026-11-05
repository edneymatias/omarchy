# Spike: autenticar no Omarchy com o celular

Pergunta que este spike responde: **um celular (Android ou iPhone) aceita criar e usar uma passkey para o Omarchy pelo transporte hybrid** (o fluxo "usar um telefone" do Chrome: QR code + Bluetooth + túnel), de forma que o PC consiga verificar a resposta sozinho?

Se sim, transformar isso em autenticação de `sudo`/polkit/tela de bloqueio é trabalho de integração (PAM), não de pesquisa.

Ainda **não** mexe em PAM. Nada no sistema é alterado; os dados ficam em `~/.config/omarchy-phone-auth-spike/`.

## Como funciona

```
enroll:  PC mostra QR → celular escaneia → Bluetooth (prova de proximidade)
         → túnel (servidor da Google/Apple) → celular cria passkey "Omarchy"
         → PC guarda só a chave pública

verify:  PC gera desafio aleatório → celular (QR, ou notificação se ficou vinculado)
         → digital/rosto → assinatura → PC confere localmente
         exit 0 = OK, 1 = recusado/inválido, 2 = erro
```

A verificação confere o que um site conferiria: desafio, origem, hash do rp id, flags de presença e de verificação do usuário (biometria/bloqueio do celular) e a assinatura ES256 contra a chave pública guardada no enroll.

O código hybrid é da [libwebauthn](https://github.com/linux-credentials/libwebauthn) (fixada no commit `e5f01db`).

## Compilar (na sua máquina Omarchy)

```bash
sudo pacman -S --needed rust base-devel pkgconf dbus systemd-libs
cd spikes/phone-auth
cargo build --release
```

O binário fica em `target/release/omarchy-phone-auth-spike`.

## Testar

Pré-requisitos: Bluetooth do PC ligado (`omarchy-bluetooth-power`), Bluetooth e internet ligados no celular, celular perto do PC.

```bash
./target/release/omarchy-phone-auth-spike enroll
./target/release/omarchy-phone-auth-spike verify
./target/release/omarchy-phone-auth-spike verify --qr   # força QR mesmo se o celular ficou vinculado
./target/release/omarchy-phone-auth-spike status
./target/release/omarchy-phone-auth-spike forget        # apaga os dados locais
```

Para ver o que acontece no transporte: `RUST_LOG=debug ./target/release/omarchy-phone-auth-spike verify`.

### O que observar

| # | Pergunta | Onde ver |
|---|---|---|
| 1 | O celular aceita criar a passkey com rp id `omarchy.localhost`? | `enroll` termina com `ENROLLED` |
| 2 | Se recusar, aceita com um domínio seu? | `enroll --rp-id seudominio.com` (rode `forget` antes) |
| 3 | A assinatura confere? | `verify` imprime `OK` |
| 4 | O celular oferece vínculo (próximas vezes sem QR)? | `enroll` imprime `Linked phone` |
| 5 | Com vínculo, chega notificação no celular e funciona? | segundo `verify` sem `--qr` |
| 6 | Quanto tempo leva? | `verify` imprime o tempo |
| 7 | A passkey aparece no gerenciador de senhas do celular? E sincroniza com outro celular da mesma conta? | Google Password Manager / Senhas (iOS) |

Teste com os celulares que tiver (Android e iPhone se der). Anote para cada um: modelo, sistema, resultado das linhas 1–6 e a mensagem de erro, se houver.

## Limitações conhecidas

- Precisa de internet nos dois lados e Bluetooth: sem isso, `verify` falha (no PAM real, cairia na senha).
- `omarchy.localhost` não é um site real; é exatamente isso que a linha 1 testa.
- O QR aparece no terminal; tela de bloqueio e polkit precisariam mostrá-lo na interface.
- Só ES256 é aceito (é o que Android e iOS usam).
- O arquivo `linked-phones.json` contém o segredo do vínculo com o celular (modo 0600). Quem o copiar consegue *pedir* autenticação ao celular, mas não autenticar sem você confirmar no aparelho.

## Testes automatizados

```bash
cargo test
```

Cobrem a verificação da assinatura com um "celular" simulado em software: assinatura válida, sem verificação do usuário, desafio reutilizado, outra chave, outro rp id, outro tipo e outra credencial.
