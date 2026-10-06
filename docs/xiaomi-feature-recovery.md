# Recuperação de recursos Xiaomi — 2026-10-05

Objetivo: reimplementar recursos ausentes com contratos recuperados do stock, não apenas fazer módulos carregarem. Trabalho em andamento; nenhum subsistema inteiro declarado recuperado.

## Referência e execução

Boot DyperOS 3.0.304 SHA256 `3c555f2f5dda7b6085dd38a2869d23ffe680c05d5bcc59625885b726690a00ce`.
Image extraída diretamente desse boot, SHA256 `99485b0132e3aa28f4e965119591c8149fe3c20e7e0fd10d753ef014a582472e`.
Kallsyms SHA256 `2b7929e77d87d54a9a2385dcc1f0a262a2fe17d7226dd304d40b5fa59dd30805`; endereço-base validado com linux_banner e BTF.

Ferramenta `scripts/recover-stock-features.py`: somente lê entradas; preserva bytes, desassemblagem, exports/CRC e referências de chamadas BL nos relatórios. Não reutiliza arquivo chamado stock_boot.img do repo. Exige diretório novo e rejeita hashes divergentes. Resultados atuais: `outputs/stock-recovery-features-20261005-v2`, relativo ao workspace.

|Família|Símbolos candidatos|Referências BL|Estado|
|---|---|---|---|
|DMA-BUF huge pages|14|68|10 corpos reconstruídos com testes delimitados; ambas variantes TLBI e dois helpers genéricos cotejados; ownership/callers e integração incompletos|
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

`dmabuf_huge_split.recovered.c` recupera `__split_dmabuf_huge_pmd`: ordem notifier start → PMD lock → teste de PMD/folio → withdraw da tabela depositada → invalidate → 512 PTEs → barreira → publicação PMD → contador → unlock → notifier end. Withdraw acontece antes de invalidate neste stock; não copiar a ordem do THP anônimo genérico como se fosse equivalente. PTEs herdam proteção VMA, WRITE/AF/dirty e marca special, com contiguity removida por set_pte_at. Bits/calls cotejados com instruções e headers ACK exatos, não inferidos só pelo pseudocódigo.

`test-dmabuf-stock-split.py`: 1.000 casos confirmados, comparando todos os 4.096 bytes da tabela, PMD, contador (incl. wrap), guardas folio/compound head, chamadas e sequência dsb/isb/dmb. Inclui PMD present/PROT_NONE/present-invalid/table/zero e flags WRITE/AF/dirty/CONT. Protótipo/enum/layouts conferidos no BTF. Helpers MM/TLB/lock modelados; execução usa instruções reais para stores/atomics/barreiras, **não** prova efeito delas na MMU/cache/coerência. BSS dos contadores/system_cpucaps explicitamente modelado, não fingido como bytes extraídos. ARM64 alternatives do Image permanecem sem patches de boot; validar variante efetiva do aparelho ainda pendente.

### Lock, remoção e percurso do intervalo

`dmabuf_huge_zap.recovered.c` recupera `__pmd_dmabuf_huge_lock` e `zap_dmabuf_huge_pmd`. Lock usa ptlock da página do PMD, não acessa VMA; reread sob lock rejeita PMD não huge. Zap limpa PMD atomicamente, estende start/end de mmu_gather e marca cleared_pmds, retira/libera tabela PTE depositada, reduz pgtables_bytes em 4096, unlock e incrementa contador. Não libera as páginas do buffer DMA-BUF. Reimplementação limitada ao split PMD ptlock do stock; gate dessa configuração obrigatório antes de integração.

`test-dmabuf-stock-zap.py`: 1.000 casos lock/zap contra ARM64, comparando retorno, PMD, 128 bytes de gather, metadados da página liberada, contadores e ordem/argumentos dos helpers. Inclui PageHead/order/nr_pages, flags gather preservadas, intervalos/range wrap e contadores u64. Helpers free/lock são modelos; não prova liberação real, TLB/SMP ou lifetime. Falha inicial do fixture: delta `int` negativo comparado como u64 sign-extended; ARM64 escreve W2. BTF confirma int32; normalização explícita ao comparar corrige fixture, não código recuperado. V39 já exige assinatura real; nenhuma alteração de contrato proposta.

`dmabuf_huge_range.recovered.c` recupera `__split_dmabuf_huge_range` e wrapper `split_dmabuf_huge_range`, restritos à geometria stock ARM64 4K/VA39/três níveis. Percorre PGDs de 1 GiB e PMDs de 2 MiB, chama split apenas para PMD huge. Com PGD table válido, exige **bit 39 da VMA**, senão BUG. Produtor confirmado: `dmabuf_huge_remap_pfn_range` marca bit39 quando `map_type=0`, além de flags comuns `0x4044400` (VM_IO/PFNMAP/DONTEXPAND/DONTDUMP). Nome original da macro ainda não comprovado; constante marcada como recuperada, não inventada como THP. Máscara PA de descriptor `0x7ffffff000` preservada, não generalizada para outra geometria.

`test-dmabuf-stock-range.py`: 500 casos, PGDs ausentes/table, PMD none/table/present/PROT_NONE/present-invalid, bordas 2 MiB/1 GiB, argumentos e parada no fim; 25 guards BUG disparados e comparados. Outros 24 prefixos ARM64 do remap confirmam seleção map_type=0, flags preservadas/comuns e vm_pgoff em COW; param-se antes de alocar/percorrrer PGD e não provam corpo remap inteiro. Split helper interceptado; prova routing, não mutações internas nem estabilidade de tabelas. Callers precisam garantir VMA não vazia/estável e bit 39 correto.

### Corpo remap, ambos os ramos

`dmabuf_huge_remap.recovered.c` reconstrói o corpo inteiro de `dmabuf_huge_remap_pfn_range`: prefixo COW, vma_start_write via vm_flags_set, percursos PGD/PMD e seleção `map_type==0` para PMD ou qualquer outro valor para PTE. Ramo PMD aloca/deposita tabela e incrementa pgtables_bytes; PTE usa pte_alloc_map_lock, exige primeira PTE vazia, monta PTE special sem CONT, set_ptes e unlock/unmap. Contadores incrementam por trecho PMD, não por página individual. Sem normalização silenciosa dos valores map_type.

Falha de alocação retorna -ENOMEM mantendo flags/vm_pgoff e mapeamentos anteriores; não existe unwind neste corpo. End de tamanho zero/wrap e addr não alinhado a 4KiB levam a BUG. COW precisa cobrir VMA inteira, senão -EINVAL. Guardas de adequação a **2MiB** não estão no corpo: `pmd_set_huge` recebe PA mascarado a 4KiB e retorno é ignorado. Ainda precisa validar caller para alinhamento/extent, não tratar esse código como API segura para buffers arbitrários.

|Teste remap|Casos|Cobertura concreta|
|---|---:|---|
|PMD|216|Flags/seq/VMA/pgoff, PGD/PMD bytes, página depositada, contador e helpers; 33 sucessos multitrecho, 16 falhas parciais, 4 rejects COW, 45 BUGs|
|PTE|360|Flags/seq, buffers PGD/PMD/PTE, máscaras SPECIAL/CONT, contadores e helper/barrier order; 60 sucessos multitrecho, 36 falhas parciais, 7 rejects COW, 87 BUGs, 70 casos PTE única e 96 bulk|

Casos de falha variam independentemente do tamanho; asserts exigem cada categoria acima não vazia. BTF valida protótipo, anonymous fields, vm_lock_seq/mm_lock_seq, vm_lock, vm_pgoff, pgd/pgtables_bytes e ptdesc.ptl. Config verificada: ARM64 4KiB, VA39, três níveis e NUMA=n. `pte_alloc_one`, `pmd_set_huge`, bulk contpte_set_ptes, alloc/map-lock/RCU são modelados, não recuperados como parte desses testes. PTE única executa stores/barreiras originais. Portanto estes testes não provam helpers, MMU, races, unwind/lifetime ou implementação em outra configuração.

Fixtures: ptlock do PMD fica em offset40 da struct page/ptdesc; fixture novo inicialmente copiou endereço da página adjacente usado pelo teste split, diferença de 64 bytes detectada e corrigida. BTF e trace agora conferem página certa. Teste PTE precisou mapear system_cpucaps BSS em contexto privado; não são bytes extraídos. V39/V40 já cobrem esses gates, nenhuma mudança de contrato de produção.

### Move: variantes arquiteturais comparadas

`dmabuf_huge_move.recovered.c`: lock rmap file→anon se solicitado; destino PMD não vazio causa BUG antes de old PMD lock. Old não huge retorna false; transferência válida limpa old atomicamente, retira/deposita tabela somente se páginas de PMD diferentes, publica entry **sem alterar soft-dirty**, faz flush se present, libera locks em ordem reversa. Diferente do helper THP genérico que aceita mais casos de destino e modifica soft-dirty. Não substituir silenciosamente por move_huge_pmd.

`test-dmabuf-stock-move.py`: 768 casos ARM64, range-TLBI ligado/desligado em contexto privado, incluindo wrap de end em ULONG_MAX. 488 movimentos, 246 rejects old, 34 BUGs de destino; 288 casos rmap, 244 transferências deposit, 91 sync_icache, 30 MTE tags; 163 casos range TLBI e 53 com TLBI individual. Compara PMDs, retorno, locks, argumentos, barreiras e operandos TLBI (opcodes SYS interceptados após registrar; efeito MMU não executado). BTF valida assinatura e offsets transitivos de VMA/file/address_space/anon_vma/mm/ptdesc. Campos system_cpucaps são BSS privado, não dados extraídos.

Modelo host reproduz algoritmo ACK exato de range TLBI (SCALE/NUM/TG, remainder individual), ASID e ASID pareado. Não prova helpers cache/tag/notifier, CPU alternatives efetivos, hardware/SMP/lifetime. Fonte usa flush_tlb_range/set_pmd_at reais na futura integração, mas ainda não compilou em Kbuild. Recurso não concluído por existirem os dez corpos: transitive helpers e callers continuam obrigatórios.

**Ressalva stock confirmada:** macro __flush_tlb_range_op avança variável start; notifier secundário é chamado depois com start já no end. 82 casos privados com notifier ativo confirmaram range vazio `start==end`; fallback ASID usa 0/ULONG_MAX. Efeito no driver/hardware ainda não comprovado. Preservar essa semântica na análise não aprova replicar eventual bug: gate de notifier/caller e decisão explícita de segurança antes de integrar.

### Helpers genéricos cotejados com fonte ACK

`test-dmabuf-stock-deposit.py` compila **corpos originais** de pgtable_trans_huge_deposit/withdraw extraídos do pgtable-generic.c com SHA256 fixo. 7.200 operações ARM64 contra C, sequências variadas de até oito tabelas, ownership/pointers/list/poison bytes e retornos; 100 violações da guarda held-lock confirmadas. BTF valida page.lru/ptdesc.pmd_huge_pte/ptl. Config real LIST_HARDENED=y, DEBUG_LIST=n, ILLEGAL_POINTER_VALUE=0xdead000000000000. Primeira suposição do fixture DEBUG_LIST=y foi rejeitada pelo gate e corrigida para config efetiva; não mudou fonte/stock. List macros host cobrem listas válidas; callbacks de corrupção, ownership real de lock e SMP pendentes.

`test-dmabuf-stock-pmd-set.py` compila corpos ACK pmd_set_huge/pgattr_change_is_safe do mmu.c com SHA256 fixo: 3.000 casos, 1.096 accepts e 1.904 rejects, PMD e barreiras comparados. Permission changes, PFN diferente, CONT, nG→global, normal/tagged e flags não permitidas. **1.095 aceitações tinham PA não alinhado a 2MiB**: VM_BUG_ON é removido por DEBUG_VM=n, confirmado no Image. Isso demonstra ausência da guarda no helper, não validade desse endereço para MMU. Fonte/constantes/helpers de encoding host não substituem teste MMU.

Esses helpers já existem no ACK; não precisam de duplicatas Xiaomi ou stubs. Ainda precisa conectar suas semânticas aos testes de sequência do recurso, não apenas repetir chamadas modeladas.

Fontes de interface em `outputs/stock-ack-mm-reference-20261005`, `stock-ack-mm-interfaces-20261005`, `stock-ack-pgalloc-reference-20261005`, `stock-ack-tlb-reference-20261005`, `stock-ack-remap-reference-20261005`, `stock-ack-move-reference-20261005`, `stock-ack-dmabuf-helpers-reference-20261005`: commit ACK exato e cada payload Git blob/SHA256 verificado. Recurso inteiro continua incompleto: demais helpers, hooks/callers/lifetime, integração e gates por validar. Nada integrado ou instalável.

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
