# Recuperação de recursos Xiaomi — 2026-10-05

Objetivo: reimplementar recursos ausentes com contratos recuperados do stock, não apenas fazer módulos carregarem. Trabalho em andamento; nenhum subsistema inteiro declarado recuperado.

## Referência e execução

Boot DyperOS 3.0.304 SHA256 `3c555f2f5dda7b6085dd38a2869d23ffe680c05d5bcc59625885b726690a00ce`.
Image extraída diretamente desse boot, SHA256 `99485b0132e3aa28f4e965119591c8149fe3c20e7e0fd10d753ef014a582472e`.
Kallsyms SHA256 `2b7929e77d87d54a9a2385dcc1f0a262a2fe17d7226dd304d40b5fa59dd30805`; endereço-base validado com linux_banner e BTF.

Ferramenta `scripts/recover-stock-features.py`: somente lê entradas; preserva bytes, desassemblagem, exports/CRC e referências de chamadas BL nos relatórios. Não reutiliza arquivo chamado stock_boot.img do repo. Exige diretório novo e rejeita hashes divergentes. Resultados atuais: `outputs/stock-recovery-features-20261005-v2`, relativo ao workspace.

|Família|Símbolos candidatos|Referências BL|Estado|
|---|---|---|---|
|DMA-BUF huge pages|14|68|3 wrappers recuperados, 3.000 testes de rotas; ownership/locks/map/unmap ainda incompletos|
|XRING LB|63|340|Interface ioctl parcialmente recuperada; handlers ainda não reimplementados|
|F2FS fastdiscard|5|1|Inclui atributos; caminhos genéricos ainda precisam ser rastreados|
|SCSI fastdiscard|0|0|CONFIG stock ativa; falta rastrear alterações nas funções genéricas|
|SCSI discard|0|0|CONFIG stock ativa; falta rastrear alterações nas funções genéricas|
|Enhanced I/O stats|69|126|Candidatos incluem I/O stats genéricos; pertencimento não inferido como certeza|
|EROFS I/O stats|13|49|9 corpos recuperados/testados offline, dispatcher sysfs e hooks mapeados; patch experimental não instalável|

Contagens por nome, com sobreposições; não são porcentagem de conclusão. Zero nomes encontrados não significa ausência de implementação. Funções comuns, inlining e acesso indireto continuam fora da classificação. Diferenças de símbolos referem-se ao candidato histórico de setembro, não ao último kernel instalado. As sete opções acima também foram confirmadas ausentes na config embutida do último artefato **local** (run 35818084380, Image SHA256 `3edcddcf2ab518c8446fc2b940a295d6dbd133345dbe89d1df26715baa3c889a`). Isso não identifica o kernel atualmente no celular.

## Módulos reextraídos e reconferidos

Backups de boot/vendor_boot/vendor_dlkm/system_dlkm passaram novamente seus SHA256. Extração EROFS somente `/lib/modules`; ramdisks lidos com parser newc próprio, caminhos inseguros/symlinks/hardlinks/truncações/duplicatas rejeitados. Não usa cpio para gravar e ignora arquivos fora de módulos.

Conjunto 6.6.77: vendor_dlkm 274, system_dlkm 78, vendor_boot 251, recovery 7 = 610 registros. Bytes/vermagic/dependências e multiplicidade coincidem com referência histórica. 78 assinaturas CMS verificadas novamente contra certificado público stock. Referência fresca em `outputs/stock-modules-reextracted-20261005/rodin-304-module-reference.json`; 3.506 imports/CRCs exigidos coincidem com Module.symvers do último artefato local, que inclui certificado stock. Todos os hashes do artefato local também passaram.

Importante: o mesmo vendor_boot contém **outros 251 módulos num diretório 6.6.89**, mantidos separadamente na extração, não misturados na referência 6.6.77. Existência no ramdisk não comprova uso/carregamento. Seleção real pelo init/load order ainda precisa de auditoria. CRC/certificado coincidentes não provam implementação funcional de recursos internos/dinâmicos nem resultado no aparelho.

## Contrato recuperado: XRING ioctl

`xring_lb_ioctl`, endereço `0xffffffc080cdd950`, normaliza o comando adicionando `0x3ef7b3ff`, compara índice unsigned com 5 e despacha pela tabela de seis bytes em `0xffffffc0812d2fc0`: `00 15 23 31 3f 4d`. Cada ramo passa o argumento original `x2` como `x0` ao handler.

|Comando|Handler confirmado no binário|
|---|---|
|`0xc1084c01`|`xring_lb_dealwith_collect_cmd`|
|`0xc1084c02`|`xring_lb_dealwith_preread_cmd`|
|`0xc1084c03`|`xring_lb_dealwith_clear_cmd`|
|`0xc1084c04`|`xring_lb_dealwith_flush_cmd`|
|`0xc1084c05`|`xring_lb_dealwith_stop_cmd`|
|`0xc1084c06`|`xring_lb_dealwith_recovery_cmd`|

Não enviar esses comandos ao dispositivo: estrutura de usuário, validação, side effects, permissões, lifecycle e interação com armazenamento ainda pendentes. Também existem gates de habilitação no início da função. A tabela não prova o contrato inteiro dos handlers.

## Corpo recuperado: EROFS início de I/O

`tools/stock-recovery/erofs_iostat_record_start.recovered.c` contém o corpo semântico reconstruído, não integrado. BTF confirma `void (struct erofs_sb_info *, struct bio *)`; ponteiro `sbi->iostat` em `0x1c0`, flag `iostat_enable` em offset 0 e `bio->android_oem_data1` em `0x88`.

O binário lê a flag; se desligada retorna sem gravar. Se ligada chama `ktime_get` e grava o retorno no campo OEM de bio. Não há guarda NULL antes de ler iostat no stock: preservar a semântica exige recuperar o contrato de inicialização/lifetime, não adicionar uma guarda e declarar equivalência.

## Avanço: EROFS, código e comparação ARM64

Os arquivos `erofs_iostat_{init,update,controls,show,sysfs}.recovered.c` mais `record_start` recuperam as nove funções próprias e o dispatcher. Tipos/offsets recuperados de BTF; header `erofs_iostat_types.recovered.h` preserva os tipos `unsigned long`, arrays e ponteiro percpu do stock, não somente tamanhos coincidentes.

|Teste diferencial|Casos confirmados|Cobertura delimitada|
|---|---:|---|
|update|10.288|Limites de tamanho/latência, janelas, overflow, estados desabilitados; contexto percpu modelado|
|record_start|6|Timestamp com flag ligada/desligada|
|config/reset|216|136 entradas parser, 80 resets por CPU; mutação de buffer e bytes das estruturas|
|daily/window show|80|Formatação stock ARM64 real, bytes/retorno, agregação com contexto modelado|
|init/destroy|58|54 inicializações com ambas as falhas de alocação, masks até CPU31; quatro destruições|
|dispatcher sysfs|304|Atributos reais; enable/disable, configuração, reset, saída; buffers e efeitos comparados|

Testes executam as instruções ARM64 originais com Unicorn 2.1.4 em RAM privada; chamadas de relógio/alocação e contexto CPU são modelados. Não há emulação de filesystem completo, scheduler, SMP, kernel inteiro ou hardware. Compilação host com `clang -Werror`; update também passou smoke ASan/UBSan. Os casos não provam cobertura completa de todos os estados possíveis.

Particularidades stock preservadas na análise: limites de size bucket 17/129/257/513 KiB, pico anormal herdado do pico normal, multiplicação de unidades com wrap u64, reset aceita prefixo `reset`, leitura das janelas usa último índice CPU elegível. Não substituir silenciosamente por heurísticas diferentes.

### Inicialização: divergências de segurança deliberadas no patch experimental

O stock aloca iostat, depois estatísticas percpu; se a segunda alocação falha, libera iostat mas **não zera `sbi->iostat`**. Teste confirmou o ponteiro pendente; ainda não confirmou double-free no caminho VFS completo. O stock publica sysfs antes de inicializar iostat. Atributo config/show não protege seu acesso interno contra iostat NULL; concorrência real ainda não foi reproduzida.

A análise C preserva os efeitos do binário. O overlay experimental difere explicitamente: zera ponteiro liberado e inicializa iostat antes de publicar sysfs. Essas diferenças não são chamadas de equivalência binária. Update/reset/show permanecem sem validação de concorrência.

### Ligações recuperadas

`erofs_fc_fill_super` chama init após register_sysfs; `erofs_put_super` chama destroy ao final. `z_erofs_runqueue` (submit_queue inlined no stock) chama record_start imediatamente após alocar bio; endio chama update antes de percorrer segmentos/decompressão. Dispatcher e objetos BTF/data confirmam:

|Atributo|ID|Permissão|Operação|
|---|---:|---|---|
|iostat_enable|2|0644|Booleano; escrever zero limpa os cinco grupos de estatísticas|
|iostat_config|3|0644|Janela em segundos e cinco thresholds em ms|
|iostat_window_latency|4|0444|Duas janelas, dados normal/anormal|
|iostat_daily_latency|5|0644|Normal/anormal/delay; escrita reset limpa grupos daily/delay|

`scripts/prepare-erofs-reimplementation.py` gera overlay + `REVIEW_ONLY.patch` a partir de sete arquivos públicos ACK no commit `f7ebe251035c0d15ff90c6a0a320697932785fad`. Cada arquivo tem SHA256/Git blob verificado; anchors ambíguos abortam. Não altera o checkout do kernel. Saída atual em `outputs/stock-erofs-reimplementation-20261005-v2`; estado **BLOCKED_NOT_INSTALLABLE**. Teste aplica patch com whitespace=error em diretório temporário e reconfere oito arquivos, preservação dos demais e rejeição de fontes alteradas. Falta Kbuild y/n (incl. ZIP), BTF/KMI, lifetime de montagem falha/desmontagem, SMP, revisão de licenciamento/estilo e hardware.

## Avanço: wrappers DMA-BUF huge pages

`dmabuf_huge_wrappers.recovered.c` recupera `vma_adjust_dmabuf_huge`, `split_dmabuf_huge_pmd_address`, `zap_split_dmabuf_huge_pmd`. Comparação com ARM64 stock: 3.000 casos, bordas de 2 MiB, end/start, adj_next positivo/zero/negativo, lookup PMD falhando, argumento freeze verdadeiro/falso e folio NULL/não NULL. As duas wrappers repassam **false** a `__split_dmabuf_huge_pmd` independentemente de freeze recebido, conforme instruções.

Teste intercepta `mm_find_pmd`, `find_vma` e split para registrar rotas/argumentos; não prova os helpers, MMU, TLB, locks ou ownership. BTF de vm_start/end está em union/struct anônimo, offsets transitivos validados (0/8/16 para start/end/mm). `adj_next>0` exige vma e next válidos: stock lê next antes de testar NULL; callers ainda precisam ser recuperados. Não há patch MM instalável.

## Verificação executada

- `python3 scripts/test-recover-stock-features.py`: seis testes; decodificação BL positiva/negativa, rejeição de instruções não-BL, boot incorreto, seleção de helpers genéricos.
- `scripts/verify-stock-recovered-contracts.py --image <stock.Image> --symbols <stock.kallsyms>`: hashes, BTF, bytes exatos da função EROFS, destinos XRING e normalização dos comandos. C recuperado compilado com clang, -Werror, ASan/UBSan; flag desligada preserva campo, ligada grava timestamp.

Passagem Ghidra atual: 107 funções candidatas/callers em `outputs/stock-ghidra-20261005-v5`, inventário/status/log verificados. Protótipos BTF importados; structs opacas exatas, layouts completos permanecem em JSON. Saída `.pseudo.c` não é automaticamente código confiável. Primeira passagem com erros de fluxo está preservada, não usada como prova. Funções homônimas retêm endereço no nome, sem descartar helpers locais.

Sem Kbuild, KMI, testes SMP ou hardware nesta etapa. Referências BL inferidas podem incluir padding/CFI; não substituem um grafo de fluxo completo. Dados extraídos não têm semântica automaticamente conhecida.

## Próximas partes técnicas obrigatórias

1. XRING: structs de comando, copy_from_user, tamanhos/limites, listas/locks, threads, cancelamento, hook pagefault/readfile e rollback de init.
2. EROFS: todos os corpos e campos, init/destroy, unidades/janelas, sysfs e concorrência; somente então patch do subsistema.
3. DMA-BUF: page tables, PMD/PTE, TLB, split/zap, VMA lifetime e todos os callers internos.
4. Discard/I/O stats: comparar funções genéricas stock com fontes públicos exatos; mapear diferenças de layout e caminhos F2FS→block→SCSI/UFS.
5. Expandir inventário para demais módulos stock e dependências; nunca limitar o objetivo às sete famílias de partida nem prometer qualquer versão.

Nenhum build remoto, assinatura alterada, flash ou acesso ao celular nesta etapa.
