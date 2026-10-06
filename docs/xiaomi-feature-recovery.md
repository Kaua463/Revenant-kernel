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

`dmabuf_huge_remap.recovered.c` reconstrói o corpo inteiro de `dmabuf_huge_remap_pfn_range`: prefixo COW, vma_start_write via vm_flags_set, percursos PGD/PMD e seleção `map_type==0` para PMD ou qualquer outro valor para PTE. Ramo PMD aloca/deposita tabela e incrementa pgtables_bytes; PTE usa pte_alloc_map_lock, exige primeira PTE vazia, monta argumento PTE special sem CONT, set_ptes e unlock/unmap. **Isso não significa saída final sem CONT:** o helper bulk real pode ativar CONT em grupos alinhados de 64KiB. Contadores incrementam por trecho PMD, não por página individual. Sem normalização silenciosa dos valores map_type.

Falha de alocação retorna -ENOMEM mantendo flags/vm_pgoff e mapeamentos anteriores; não existe unwind neste corpo. End de tamanho zero/wrap e addr não alinhado a 4KiB levam a BUG. COW precisa cobrir VMA inteira, senão -EINVAL. Guardas de adequação a **2MiB** não estão no corpo: `pmd_set_huge` recebe PA mascarado a 4KiB e retorno é ignorado. Ainda precisa validar caller para alinhamento/extent, não tratar esse código como API segura para buffers arbitrários.

|Teste remap|Casos|Cobertura concreta|
|---|---:|---|
|PMD|216|Flags/seq/VMA/pgoff, PGD/PMD bytes, página depositada, contador e helpers; 33 sucessos multitrecho, 16 falhas parciais, 4 rejects COW, 45 BUGs|
|PTE|360|Flags/seq, buffers PGD/PMD/PTE, máscaras SPECIAL/CONT, contadores e helper/barrier order; 60 sucessos multitrecho, 36 falhas parciais, 7 rejects COW, 87 BUGs, 70 casos PTE única e 96 bulk|

Casos de falha variam independentemente do tamanho; asserts exigem cada categoria acima não vazia. BTF valida protótipo, anonymous fields, vm_lock_seq/mm_lock_seq, vm_lock, vm_pgoff, pgd/pgtables_bytes e ptdesc.ptl. Config verificada: ARM64 4KiB, VA39, três níveis e NUMA=n. `pte_alloc_one`, alloc/map-lock/RCU permanecem modelados nesses testes. **Depósito e pmd_set_huge agora executam corpos stock no teste PMD**, além de suas comparações separadas abaixo. PTE única e **contpte_set_ptes bulk executam instruções stock**, incluindo stores e barreiras. Não prova MMU, races, unwind/lifetime ou implementação em outra configuração.

Melhoria do teste transitive: modelo bulk inicial apenas incrementava PFNs, ocultando o efeito CONT do helper que era interceptado. Revisão de fonte ACK/pseudocódigo identificou a lacuna; modelo corrigido para grupos de 16 PTEs/64KiB e interceptação removida (chamada só observada, corpo stock executado). Mesmos 360 casos passam, com 42 casos contendo saída CONT e 157 com saída não-CONT; toda PTE nova permanece SPECIAL. Não foi necessário alterar C remap, que já chamava set_ptes real. Demais ramos contpte não usados por esses inputs continuam fora da cobertura.

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

### Primeiro encadeamento com estado real dos helpers

`test-dmabuf-stock-remap-pmd.py` não intercepta mais pgtable_trans_huge_deposit/pmd_set_huge: observa argumentos e executa seus corpos ARM64 stock. Host compila corpos ACK com os hashes acima, somente renomeando funções para permitir wrappers de trace. Constantes/encoding e macros list/set_pmd continuam explícitos no fixture, não extraídos magicamente. Verifica LIST_HARDENED/DEBUG_LIST/DEBUG_VM/ILLEGAL_POINTER_VALUE e BTF page.lru/ptdesc.pmd_huge_pte/ptl. Compara metadados de todas as páginas, owner/list, PMDs e barreiras. Lock modelado marca bit held usado pela guarda do corpo real; BSS/counters continuam contexto privado.

Mesmos 216 inputs passam. Após cada remap sem BUG, teste continua **sem reset dos metadados** para withdraw de cada tabela depositada: 173 tabelas distintas retiradas, incluindo 16 sequências após remap retornar -ENOMEM com depósitos parciais. Corpo withdraw stock executado contra ACK C; retornos/lista/poisons/owner comparados, owner termina NULL, nenhum retorno duplicado. PMDs e pgtables_bytes permanecem iguais: withdraw sozinho **não** limpa mappings, libera tabela ou decrementa accounting. Não chamar modo withdraw de teardown completo ou prova de ausência de leaks. Lock held para withdraw é injetado no contexto privado, não adquirido por caller real. Modo zap abaixo acrescenta clearing/free/accounting; split/move ainda pendentes no encadeamento.

Fixture PTE passa a consumir builder hash-verificado dos helpers para manter fonte compartilhada consistente; seus 360 casos e cobertura CONT permanecem iguais. Nenhum helper PMD é usado pela rota PTE testada. Dependência local: fontes em outputs/stock-ack-dmabuf-helpers-reference-20261005 relativas ao diretório do Image; falta/hash incorreto aborta, não usa fallback.

Regressão DMA completa deste checkpoint passou com os mesmos limites explícitos (split 200 default); rerun PMD/PTE após garantir alinhamento do metadata host e sizeof/page.lru também passou. Sem alterar recipes/produção, workflow, config ou device.

### Encadeamento remap → zap e tentativa repetida

Mesmo teste aceita `--teardown zap` (default continua withdraw). Sem reset do estado produzido pelo remap, executa zap_dmabuf_huge_pmd e seu __pmd_dmabuf_huge_lock ARM64 reais para cada PMD publicado, com withdraw/deposit/pmd_set_huge stock reais; C compila a reconstrução zap existente e corpos ACK. 216 casos remap, 173 tabelas retiradas/liberadas no modelo de alocador, incluindo 16 cadeias após falha parcial. Compara PMDs, metadata/list/poison/page_type, owner, mmu_gather inteiro, contador zap, pgtables_bytes e helper order a cada etapa. Todos os PMDs terminam zerados, owner NULL e pgtables_bytes retorna ao valor inicial (inclui wrap u64 inicial). 123 chamadas zap repetidas no PMD já vazio retornam zero, sem nova free/contador/accounting. Cada __free_pages observado precisa apontar a tabela alocada e ser único na cadeia; double free falha assert.

BTF adicional valida mmu_gather size/offsets/cleared_pmds e delta int32 de __mod_lruvec_page_state; trace normaliza argumento int à largura ABI correta. Não injeta tabela independente entre remap e zap. Locks continuam modelados (bit held privado), __alloc_pages/__free_pages e mod_lruvec também; liberar no modelo não prova alocador real. Testa PMDs inicialmente vazios, file/anon ausentes e páginas de tabela não compound. Sem unmap caller completo conectado, TLB flush efetivo, split/move no meio, races, refcounts, MMU ou hardware. Nenhum patch de produção/integração/flash.

Regressão após modo zap: todos os diferenciais DMA anteriores + modo zap + deposit/pmd_set/BTF passaram (split 200 default). Ambos os modos preservam os 216 inputs de remap e seus rejects/BUGs; BTF/fonte/config seguem fail-closed.

### Encadeamento remap → move na mesma página PMD → zap

Modo `--teardown move-zap` executa corpo move_dmabuf_huge_pmd stock entre remap e zap, contra C reconstruído existente, sem reinicializar owner/list ou tabelas. 173 moves na mesma página de PMDs, 16 cadeias de falha parcial prévia; clearing old/publicação new/retorno/accounting/metadados/helper/barrier/TLBI trace comparados após cada etapa. Depósitos e metadados permanecem byte-a-byte iguais durante move; depois os destinos são removidos, owner drena, pgtables_bytes restaura inicial, 123 zaps repetidos não free novamente. Destinos privados ficam nos índices 128+ da mesma tabela PMD; não significa mremap de VMA real, apenas encadeamento dos helpers. Tabelas inicialmente vazias, nenhum mapeamento externo/remapeamento concorrente.

Perfil arquitetural privado explícito: ASID=0, sem ASID pareado, range-TLBI, MTE ou notifier secundário; system_cpucaps BSS zero, mm.context/notifier_subscriptions zero. TLBI ASID é registrado com opcode/operando e pulado no emulador, não invalida MMU. Sync icache modelado; rmap false, file/anon NULL. Tipos/offsets BTF adicionais validados. Move dentro da mesma página PMD **não** executa transferência withdraw/deposit entre owners; modo distinto abaixo cobre esse ramo. Split, caller VMA/lifetime, SMP, alternativas aplicadas no boot e hardware continuam gates. Sem integrar/flash.

Regressão após move-zap: suíte DMA completa, modos withdraw/zap/move-zap, helpers ACK separados e BTF passaram; split com default 200. Nenhuma mudança de recipe/produção/config/workflow/device.

### Encadeamento entre páginas PMD diferentes

`--teardown cross-move-zap`: segundo buffer PMD privado de 4KiB e segundo ptdesc de 64 bytes, com owner/ptl próprios e offsets BTF já verificados. Não combina artificialmente os dois owners; pmd_huge_pte/pmd_lockptr host selecionam descriptor da página correta. 173 moves executam corpo stock move com locks old→new, withdraw real no source, deposit real no dest, publicação e unlock new→old; contra reconstrução C + corpos ACK. Ambos os buffers PMD e os dois descriptors/listas são comparados a cada move/zap. Mesmo perfil arquitetural limitado descrito acima.

Além do diferencial, checks independentes percorrem ambas as listas circulares: next/prev recíprocos, range/alinhamento dos nodes, ciclos válidos e nenhum node duplicado. União das listas precisa ser exatamente o conjunto de tabelas alocadas menos retiradas/liberadas, e interseção vazia. Depois de cada move cross, old contém N-step-1, new contém step+1. Source owner drena após último move; zap no destino esvazia ambos, limpa todos os PMDs e restaura accounting. Inclui 16 cadeias de remap parcial e 123 zaps repetidos sem free extra. Lock/free seguem modelos privados, sem prova de exclusão real/allocator/MMU/SMP.

Modos anteriores mantidos e passaram com esses novos checks. Segundo buffer existe só no fixture: não instala PGD/VMA para destino real, não prova mremap caller, novo alocador ou hardware. PTE fixture mantém somente sua rota anterior. Split encadeado limitado coberto abaixo; permanecem PTE teardown, callers/lifetime/consumidor real, integração/Kbuild/KMI/SMP/hardware.

Regressão deste checkpoint: quatro modos de remap/teardown, todos os demais diferenciais DMA, helpers ACK separados e BTF passaram (split default 200). Fonte/config/hashes/BTF gates preservados. Sem alterações de produção/workflow/config/flash.

### Encadeamento remap → [cross move] → split

Modos `--teardown split` e `--teardown cross-move-split`: tabela retirada do pool real gerado pelo remap (e transferido por move, no segundo modo), sem substituir por tabela independente. Corpo __split_dmabuf_huge_pmd stock executa stores e barreiras; withdraw ACK/ARM64 reais. Host compila reconstrução split existente, recebe mesma identidade page/pgtable e codifica buffers PTE privados para oito páginas. Em cada modo 173 tabelas convertem-se em 88.576 PTEs, incluindo 16 cadeias de falha parcial prévia; cross-move-split inclui 173 movimentos entre owners antes da divisão. Comparados dois buffers PMD, todos os PTEs, dois descriptors/listas, accounting, contador split, argumentos/helpers/barreiras após cada etapa. Checks independentes exigem SPECIAL, ausência CONT, progressão PA em 4KiB, PMD table apontando tabela retirada única e conservação dos pools menos tabelas convertidas.

123 tentativas split repetidas em PMD já table não retiram tabela extra nem incrementam contador; mantém PTEs/accounting/owner. A tabela convertida não é liberada: pgtables_bytes permanece no valor pós-remap, pois a página agora é tabela PTE publicada. `__free_pages` não pode ser chamado neste caminho; assert exige nenhum free modelado. Pools acabam vazios, mas tabelas publicadas continuam vivas — **não** declarar teardown completo ou ausência de leak antes de validar remoção PTE e free de page tables.

BTF adicional valida protótipo split, vm_page_prot, mmu_notifier_range e MMU_NOTIFY_CLEAR. Perfil privado sem notifier/MTE/rmap, folio NULL; guarda folio só no teste isolado. pmdp_invalidate é modelado (retorna old e limpa VALID); seu flush TLB não executado aqui. Encoding pmd_populate/PA/VA, alocação/free/locks e callbacks continuam fixtures, não MMU real. Buffers PTE zerados privados correspondem somente ao contexto de teste; não são dump extraído. Não testa callback VMA, uso real pelo GPU ou acesso hardware. Nenhuma integração/flash.

Regressão deste checkpoint: seis modos de encadeamento, PTE-remap e demais diferenciais DMA, helpers ACK separados e BTF passaram; split isolado default 200. Recipes/produção/config/workflow/device preservados. Remoção das PTEs publicadas e liberação final das page tables ainda pendentes.

### Callers: inventário dedicado e primeiro hook executado

Preparação/decompilação `--scope dmabuf` gera somente dez funções DMA + onze callers/helpers pedidos, sem decompilar XRING/EROFS/outros recursos. Saída `outputs/stock-ghidra-20261005-dma-v6`, preparação `stock-decompiler-prep-20261005-dma-v6`: 21 corpos, 21 protótipos BTF, logs/status/manifest validados. Ghidra limitado a heap 1GiB e duas CPUs; processo terminou. Pseudocódigo permanece evidência não reimplementação.

|Caller|Rota stock observada|Estado da prova|
|---|---|---|
|copy_page_range|Com bit39 após needs_copy, split source e limpa bit39 em source/destination antes de page-table copy|64 casos ARM64 com tabelas source vazias; split modelado, flags e seq/locks comparados|
|unmap_page_range|Bit39 + huge: zap para 2MiB completos; split em trecho parcial; caso contrário continua PTE|560 casos ARM64, rota DMA/genérica, PTEs vazias e retry com tabela desaparecendo; PMD helpers/locks/flush modelados|
|move_page_tables|Bit39 + huge: tenta move para 2MiB completos; split se parcial/move falha|480 casos ARM64 na rota DMA, retorno parcial e notifier order; PMD helpers/alloc/notifiers modelados|
|vma_expand/vma_shrink|Seleciona adjust DMA em vez de adjust THP com bit39; antes de mudar start/end|48 casos ARM64 sem VMA adjacente, routing/order/bounds e -ENOMEM; maple/locks/adjust modelados|
|__split_vma|Adjust DMA com limite novo antes de mudar VMA|144 casos ARM64 + 4 guards, bounds/pgoff/seq e cleanup; dup/tree/locks/adjust modelados, vm_ops/file NULL|

`dmabuf_huge_hooks.recovered.c` contém somente recipe do hook fork, não arquivo a instalar/exportar. `test-dmabuf-stock-fork-hook.py`: executa copy_page_range inteiro com PFNMAP forçando needs_copy e PGDs vazios, flag39 ligado/desligado no source/dest, seqs iguais/diferentes; compara clearing de ambas VMAs e split→locks. BTF valida campos/protótipo. Não testa cópia de PTE, split real ou concorrência/lifetime.

`dmabuf_huge_unmap_hook.recovered.c` contém recipe para ramo bit39 em zap_pmd_range, substituindo somente decisão THP genérica: huge+extent 2MiB tenta zap; retorno true avança; zap false cai para PTE **sem split explícito**; extent parcial faz split antes de PTE. `test-dmabuf-stock-unmap-hook.py` executa unmap_page_range inteiro contra recipe C compilado com -Werror: 560 casos, bit39 ligado/desligado, fullmm, VM_EXEC/PFNMAP/MIXEDMAP, PGD ausente, PMD none/table/huge/devmap/swap, fronteiras 2MiB/1GiB, retorno zap zero/um. Compara trace, flags mmu_gather e PMDs. 88 chamadas zap DMA, 90 split DMA, 144 zap genérico, 149 split genérico, 590 PTE lookups; 296 loops stock de PTEs vazias, 280 flush finais. BTF valida assinatura/campos e bitfields gather.

Primeiro fixture NULL-PTE manteve PMD estável: caller repetiu trecho até instruction bound, corretamente falhando teste. Causa do fixture, não bug stock comprovado. NULL agora modela tabela desaparecendo e PMD zerado; outro modo devolve tabela PTE vazia e executa loop stock, com lock/unlock/RCU helpers modelados. Os dois modos explicitamente distintos; sem PTE preenchida, folio freeing ou MMU/SMP/lifetime proof. V39 já exige separar routing e semântica; nenhuma alteração no código de produção ou SPEC aprovada por essa falha.

`dmabuf_huge_move_hook.recovered.c` contém recipe do ramo bit39 em move_page_tables: extent completo tenta move; falha ou extent parcial faz split; sucesso consome extent sem PTE fallback. `test-dmabuf-stock-move-hook.py`: 480 casos ARM64 do caller inteiro, comparados com C recipe; PGDs/PMDs privados, fronteiras 2MiB/1GiB, zero length, source PGD ausente, source PMD none/table/huge, rmap flag, dest PGD ausente com -ENOMEM, PTE allocation -ENOMEM, notifier ligado/desligado. 45 tentativas move, 99 split, 148 falhas PMD allocation, 136 falhas PTE allocation; 200 pares notifier start/end, 11 retornos parciais, 116 retornos completos, 80 zero-length. Compara bytes movidos, PMDs e argumentos/order, BTF assinatura/layout. Não confunde bytes retornados com páginas realmente copiadas: zero mappings podem ser apenas pulados. Não executa corpos PMD helpers/notifiers nem move de PTE preenchida; rota genérica sem bit39 permanece fora deste teste.

`dmabuf_huge_vma_hook.recovered.c`: recipe para seleção adjust DMA/THP, ambos adj_next=0, depois de vma_prepare e antes de mudar bounds. `test-dmabuf-stock-vma-hooks.py` executa vma_expand/vma_shrink inteiros com VMA adjacente NULL, seq igual/diferente, bit39 ligado/desligado, mudanças de start/end e falha preallocate: 48 casos. Confirma que expand faz lock antes de preallocate, shrink depois de preallocate com sucesso; adjust vê limites antigos. Shrink faz mas_store_prealloc antes de atualizar bounds; expand depois. Compara argumentos/order, vm_start/end/pgoff/lock_seq, retorno -ENOMEM e BTF layouts/protótipos. Maple-tree/locks/adjust modelados: sem merge/anon clone, split real, VMA lifetime ou concorrência.

`test-dmabuf-stock-split-vma-hook.py` compara caller __split_vma inteiro contra C com recipe adjust existente: 144 casos (bit39, lock_seq, new_below, pontos de corte, sucesso/falhas dup/preallocate/anon clone) e 4 BUG guards fora/no limite VMA. Compara old/new vm_start/end/pgoff/lock_seq, retorno e ordem dos helpers com snapshots dos limites; BTF inclui vma_prepare.insert e assinatura completa. 36 sucessos, 36 falhas dup, 36 preallocate e 36 anon clone. Falha dup não chama free; preallocate free new; anon clone mas_destroy→free new. Sucesso new_below ajusta pgoff original e chama mas_find depois de vma_complete; sem new_below ajusta pgoff da duplicata e reduz end original. Ajuste DMA/THP recebe sempre old vm_start e corte, adj_next=0, antes de mudar original. vm_ops/file NULL: callbacks may_split/open e file refcount não cobertos. vm_area_dup/free, anon clone, tree/locks/adjust modelados; duplicata privada não prova allocador real, MMU/refcounts ou lifetime/SMP.

Após incluir split-VMA, rerun de todos os diferenciais DMA acima (split com default 200), deposit/pmd_set e BTF unit tests passou. Somente fixtures/doc mudaram; recipes existentes preservados. Sem integração/flash.

Recipes não instalados/exportados. Diferenciais callers não substituem testes encadeados com helpers reais, ownership/unwind, Kbuild/KMI e hardware. Próximos gaps: VMA adjacente/merge, callbacks/refcounts e sequência remap→move→split→zap.

Regressão deste checkpoint: wrappers 3.000, range 500 + 24 prefixos, zap 1.000, split 200, remap PMD 216/PTE 360, move helper 768, fork 64, novos callers 1.088, deposit 7.200 passos, pmd_set_huge 3.000, BTF 3 unit tests, scope 3 unit tests e inventário Ghidra 21 saídas: todos passaram. Split 200 é o default nesta execução, não alegação de rerun dos 1.000 casos anteriores. Sem Kbuild, integração, build remoto ou device neste checkpoint.

Ativação do produtor ainda não comprovada: varredura B/BL do text normal não achou caller externo de dmabuf_huge_remap_pfn_range; nenhum pointer absoluto para entry no Image. Nome literal único está em BTF, não em lookup string observado. Nas 18 versões únicas dos módulos GPU/Mali/heap/ion selecionados da ROM 6.6.77, nenhum ORR imediato simples do bit39 encontrado. Busca estreita não cobre masks combinadas, indireção ou todos setters: **não conclui que recurso nunca é usado**, nem que ativá-lo traria ganho no aparelho. Caminho de consumo/produtor real continua gate.

Fontes de interface em `outputs/stock-ack-mm-reference-20261005`, `stock-ack-mm-interfaces-20261005`, `stock-ack-pgalloc-reference-20261005`, `stock-ack-tlb-reference-20261005`, `stock-ack-remap-reference-20261005`, `stock-ack-move-reference-20261005`, `stock-ack-dmabuf-helpers-reference-20261005`: commit ACK exato e cada payload Git blob/SHA256 verificado. Recurso inteiro continua incompleto: demais helpers, hooks/callers/lifetime, integração e gates por validar. Nada integrado ou instalável.

### Encadeamento: PTEs publicadas → unmap → retirada das tabelas

`test-dmabuf-stock-remap-pmd.py --teardown split-unmap` e `cross-move-split-unmap` continuam nos buffers realmente produzidos pelos corpos stock remap/move/split em contexto privado, sem substituir PTEs por uma tabela vazia. Cada modo mantém 216 inputs, 173 tabelas/88.576 PTEs, incluindo 16 cadeias de falha parcial. Executa `unmap_page_range` inteiro: por tabela remove uma página, trecho central, restante via intervalo completo e repete no mesmo intervalo já vazio. 692 chamadas/mode; 88.576 PTEs removidas/mode. Oráculo independente limitado a SPECIAL/PFNMAP compara todos os buffers PTE, gather start/end/cleared_ptes, ordem lookup→flush pending→unlock→RCU unlock→flush final, preservação PMD/metadados e accounting. Guardas proíbem caminho backing-page/RSS/print_bad_pte. VM ops NULL, PTEs sem CONT; lookup/lock/RCU/TLB são modelos, não MMU/SMP/lifetime. Tabelas continuam alocadas após unmap.

`--free-split-tables`, permitido somente nesses dois modos, acrescenta `free_pgd_range` stock real sobre cada tabela já vazia, com floor/ceiling que **preservam a tabela PMD pai**. 173 retiradas e 173 repetições inertes/mode: PMD limpa, page_type recebe bit 0x200 no destructor, NR_PAGETABLE decrementa, `tlb_remove_table` recebe descriptor correto após clearing, pgtables_bytes cai exatamente 4096/tabela e restaura valor inicial (wrap u64 incluído). Executa os corpos stock `tlb_remove_table`, `tlb_flush_mmu` e `tlb_remove_table_rcu`, sem interceptar sua lógica: compara batch nr/tables, flush→call_rcu, ausência de free antes do callback, descriptor original chegando a free_page_and_swap_cache e free da página batch. Cada tabela alocada/convertida é enfileirada e liberada uma única vez no modelo. Callback só invocado após driver avançar grace period **modelado**; allocator, TLB e SMP/RCU reais não comprovados. BTF valida protótipo free_pgd_range, cleared_ptes/freed_tables, layouts batch/active/local e config RCU. Não testa free da tabela pai.

Nova passagem Ghidra `outputs/stock-ghidra-20261005-dma-free-v1`, preparação `stock-decompiler-prep-20261005-dma-free-v1`: 15 corpos/protótipos, incluindo free_pgd_range, tlb_remove_table, tlb_flush_mmu, tlb_finish_mmu e tlb_remove_table_rcu; inventário/log/status validados. Sem autoanálise integral; heap 1GiB/duas CPUs. Referências ACK `stock-ack-dmabuf-free-reference-20261005/mm/mmu_gather.c` SHA256 `129bfb331764a879f2f2ad3ec9776f4fc813e16b2e256b6c62f26e9091ec58ea` e `arch/arm64/include/asm/tlb.h` SHA256 `e1de1d798cd5eca8e2ac7d6e70accee98f5723b797ec0bfdb757f181c403b108`, Git blobs e pin f7ebe251 verificados. Pseudocódigo evidencia enqueue/flush/callback separados e fallback allocation failure com flush→SMP sync→free; ainda exige teste semântico.

Teste adicional `test-dmabuf-stock-table-rcu.py`: 16 sequências queue/flush/callback contra oráculo independente delimitado, 7.134 liberações de tabelas e 11 callbacks. Exercita 0/1/2/508/509/510/1.018/1.019 tabelas, com sucesso e falha de alocação; limite batch 509, lista/contagem, deferimento até callback, flush repetido vazio, ausência de double free e fallback flush→SMP sync→free comprovados no contexto privado. Corpos stock de queue/flush/callback executados; allocator/TLB/SMP sync/grace period modelados. Descriptors sintéticos no teste separado, sem leitura das páginas reais; a sequência DMA acima prova identidade originada no remap. Ambos continuam sem prova de MMU, SMP/lifetime ou integração.

Regressão: seis modos de encadeamento anteriores, PTE-remap 360, wrappers/range/zap/split/move e todos os callers, deposit 7.200 passos, pmd_set_huge 3.000 e três BTF unit tests passaram. Split isolado default 200. Modos novos passaram com e sem retirada de tabelas. Nenhuma recipe, config/workflow, produção ou device alterado; integração/RCU/SMP/Kbuild/KMI/hardware continuam pendentes.

### Preparação da integração DMA — base e limites de hooks

Workflow audit-rodin-6.6.77-ksun-susfs.yml reconferido: KMI_TAG android15-6.6.77_r00, tag object 79d26ca363880c3c6f7841045e46427bee6c3c3b, commit f7ebe251035c0d15ff90c6a0a320697932785fad. SPEC mantém descrições antigas 6.6.102; não foi reescrito nem usado como evidência do alvo atual. `outputs/stock-ack-dmabuf-overlay-reference-20261005` contém 11 arquivos necessários (MM mmap/mremap/memory/huge_memory, Kconfig/Makefile, headers MM/pgtable), cada Git blob/SHA256 verificado no pin. Fetcher permite explicitamente somente mm/Kconfig e mm/Makefile além dos C/headers já aceitos; três testes preservam rejeição de outros build files, traversal/normalização/paths absolutos.

**Não substituir globalmente todas as chamadas vma_adjust_trans_huge.** ACK mmap.c possui cinco sites: expand, shrink, vma_merge, split-VMA e do_brk_flags. Stock `vma_merge` span inferido 1.852 bytes possui BL em 0xffffffc0803370d8 para **vma_adjust_trans_huge**, não para DMA; copy_vma chama vma_merge. Site do merge passa adj_start potencialmente não zero, ao contrário dos três callers DMA já verificados. Overlay deve preservar esse caminho genérico e aplicar seleção DMA somente nos sites comprovados no stock; do_brk_flags ainda precisa cotejo binário antes de qualquer decisão. Fonte ACK isolada não autoriza inventar hook. Nenhuma integração aplicada neste checkpoint.

### Overlay DMA e auditoria de compilação separados

`prepare-dmabuf-reimplementation.py` gera seis arquivos/patch sobre fontes ACK pinadas, com hashes fixos de todos os 11 inputs e dez recipes. Dez corpos DMA e quatro contadores agregados no huge_memory.c existente; helpers genéricos deposit/withdraw/pmd_set_huge reutilizados, não duplicados. Header xiaomi_dmabuf_huge.h declara contratos e hooks inline; CONFIG_XIAOMI_DMABUF_HUGETLB default n exige ARM64/4K/VA39/THP/HUGE_VMAP/SMP e compile guard 3 níveis/split PMD locks. Fork após needs_copy; unmap/move selecionam ramo bit39 sem cair no THP genérico; adjust somente expand/shrink/split-VMA. Nenhum export/KMI/header de layout modificado. `do_brk_flags` também cotejado: span inferido 1.072 bytes, BL 0xffffffc08033ae94 para vma_adjust_trans_huge — preservado junto ao merge.

Artifact versionado `tools/stock-recovery/overlays/dma-6.6.77`: patch, manifest e fragments enabled/disabled. `outputs/stock-dmabuf-overlay-20261005-v3` é a geração atual (v1 anterior contém newline excedente detectado pelo teste, não usada). Cinco testes do gerador comprovam recipes incorporadas, caminho disabled byte-identical salvo delimitador EOF, hooks genéricos preservados, anchors exclusivos, aplicação/reversão em árvore temporária e rejeição de drift antes da escrita. Falha inicial era newline adicional fora do #ifdef do fork; corrigida no gerador, sem alterar semântica/recipes. Invariantes V35/V39 existentes cobrem o caso; SPEC não alterado sem autorização.

`validate-dmabuf-overlay.py` valida fontes, recipes, manifest, scope de seis paths e reconstrói patch canônico antes de dry-run/aplicação opcional a árvore descartável. Cinco testes cobrem aplicação, segunda aplicação rejeitada, patch adulterado mesmo com checksum atualizado, posthash inventado, status READY indevido e preservação de header pré-existente. Manifest permanece REVIEW_ONLY_NOT_INSTALLABLE; hazards stock preservados/documentados, não corrigidos silenciosamente. Falta validar caller alignment/ownership/unwind e MMU/SMP/lifetime/hardware antes de uso.

Workflow separado `audit-rodin-dma.yml` preparado: ACK/tag object exatos, dois perfis sequenciais DMA disabled/enabled, LTO none/4K, build GKI de auditoria sem KSU/SUSFS/network e **sem pacote de flash/release/device**. Não muda workflow de uso diário. Auditor ELF/config exige dez funções e quatro counters de 8 bytes somente no enabled, ausência no disabled, geometria e split locks; aliases de artifacts só aceitos com conteúdo idêntico. Cinco testes negativos do auditor passaram; YAML validado no Ruby/Psych local. Isso é auditoria de build shape, não comprovação de runtime ou autorização de instalação.

SUSFS pin be7b7ef49a1e1b189c3abf00eacaa7ebdb4168c1 conferido via objeto Git local (checkout atual distinto não tratado como referência). AS_FLAGS_SUS_MAP=39 é bit de address_space.flags, **não** vm_flags: não é colisão com DMA. Patch SUSFS em memory.c afeta include e __access_remote_vm, não os hooks DMA recuperados; composição e gate do manifest global ainda precisam de teste na integração KSUN/SUSFS.

Atualização: geração atual `outputs/stock-dmabuf-overlay-20261005-v4` acrescenta restrição little-endian explícita no Kconfig; auditor ELF rejeita big-endian. Patch/manifest versionados regenerados canonicamente e revalidados. `test-dmabuf-susfs-composition.py` passou: patch SUSFS SHA fb8ed4e... e susfs_def.h SHA 4eef49b... exatos; única interseção MM relevante é memory.c; aplicar DMA→SUSFS ou SUSFS→DMA em árvores descartáveis resulta nos mesmos bytes de todos os inputs/header. Gate normal corretamente rejeita source pós-SUSFS: composição não habilita aceitar preimage divergente silenciosamente. Ainda falta composição do manifest global e build completo com KSUN/SUSFS.

Regressão após overlay: wrappers/range/zap/split/move/fork/unmap/move-caller/VMA/split-VMA, seis modos remap anteriores, dois modos split-unmap com retirada+RCU, PTE-remap 360 e RCU 16 sequências passaram; split isolado default 200. Recipes originais preservadas. Três suites novas totalizam 15 testes (gerador, validator, config/provider gates); composição SUSFS passou separadamente. Auditoria Actions será disparada somente depois desses gates locais, sem installer/release/flash.

### Gate de composição DMA depois do SUSFS

`validate-dmabuf-susfs-overlay.py` acrescenta validação separada, sem relaxar o validator pristine nem alterar o manifest global KSUN/SUSFS. Reconstrói duas árvores descartáveis a partir dos 11 inputs ACK exatos: SUSFS sem DMA e SUSFS com DMA. Patch SUSFS é lido do objeto be7b7ef49a1e1b189c3abf00eacaa7ebdb4168c1 e validado por SHA256; interseção com todos os inputs DMA deve ser somente mm/memory.c. Overlay original primeiro passa pelo validator canônico completo. Todos os preimages da árvore alvo e todos os postimages são cotejados byte/hash; qualquer alteração extra, symlink ou header existente bloqueia antes de aplicar. Evidência opcional não sobrescreve arquivo existente. `--apply-review` permitido apenas na árvore de build descartável; não gera installer.

`test-dmabuf-susfs-overlay.py`: seis testes passaram, cobrindo dry-run sem mutação, aplicação/resultado e repetição rejeitada, drift em memory.c e mm_types.h, reference drift, patch drift, header próprio/symlink e evidência própria preservada antes de qualquer write. A receita DMA não mudou. Gate cobre **somente os inputs DMA**, não confirma por si só toda a integração root. Próxima integração deve executar primeiro o script KSUN/SUSFS original até seu ordered manifest final, depois este gate; ainda pendentes build composto, KMI, produtor/unwind, callbacks/refcounts, MMU/SMP/hardware. Nenhum device/flash.

Auditoria isolada Actions 37406739074, head 96eaa013b59c682058a168be65b2109810944e8a: último snapshot deste checkpoint comprova Fetch pinned ACK e Apply exact review overlay com sucesso; Compile audit kernel do perfil disabled em execução, enabled na fila. Não é resultado de compilação concluída.

### Split-VMA com callbacks e referências de arquivo

`test-dmabuf-stock-split-vma-hook.py` ampliado de 144 para 1.152 casos: matriz DMA/THP, seq igual/diferente, direção/ponto de divisão, falhas dup/preallocate/anon clone, arquivo presente/ausente e vm_ops ausente/sem may_split ou open/com callbacks/com recusa. Quando vm_ops existe, close está configurado, mas esse checkpoint ainda não o executava. BTF valida offsets vm_operations_struct.open/close/may_split e file.f_count/f_mapping, além dos protótipos open(void, VMA*) e may_split(int, VMA*, unsigned long). O corpo ARM64 stock executa o incremento inline real de get_file sobre contador privado iniciado em 17; não intercepta esse incremento. C host independente compara ordem de helpers/callbacks, bounds antigos/novos, pgoff, lock_seq, retorno e contador em cada snapshot.

576 chamadas may_split, 72 open; recusa -EBUSY ocorre antes de dup; dup/preallocate/anon clone failures não incrementam file count e não chamam open. Sucesso com arquivo incrementa uma vez antes de open; close não é chamado por split. Quatro boundary BUG guards mantidos; duas novas CFI guards com tag incorreta comprovam parada antes do callback correspondente. Tag errada de open ocorre depois de get_file, contador 18 no trap: **não é retorno recuperável nem prova de unwind**, e não propõe desabilitar CFI. Callback bodies, dup/free, tree/locks/anon clone e ajuste permanecem modelados; sem prova de contador concorrente, close/fput final, MMU ou lifetime. Recipe/overlay/produção inalterados.

### Encadeamento da integração root → DMA

`integrate-dmabuf-after-root.py` implementa a sequência de integração em checkout de build ACK f7ebe251 inicialmente limpo (inclusive untracked). Antes de writes, verifica as 11 fontes contra objetos Git/hashes e o overlay canônico. Preserva gates de KSU pin/ancestry v3.3/UAPI tree/Natives blob/minimum version do workflow existente. Executa **o integrator root original sem mudanças**, com seus pins, normalizações e manifest final; exige retorno zero. Gate independente reconfirma os 26 tracked paths e ordered manifest ceb50cf6..., mais hashes dos três arquivos SUSFS copiados. Só então aplica o validator de composição DMA e exige que o conjunto final de tracked paths seja exatamente a união root + delta DMA. SUSFS copiado permanece byte-identical. Evidence registra manifest root e composto, pre/postimages e limites; não emite installer nem toca device. Falha deixa a árvore descartável para diagnóstico, não faz reset/cleanup destrutivo.

`test-dmabuf-root-integration-gates.py`: sete unit tests passaram — serialização independente/path order, duplicate/traversal, count/hash/root source drift, symlink, HEAD incorreto, dirty checkout, evidence existente, manager/API pins. Fixtures sintéticos/mocks **não comprovam execução completa do integrator**. Rerun dos seis testes do composto passou. Driver foi preparado, mas ainda precisa rodar com fontes completas/pinadas no runner e compilar; nenhum resultado composed Kbuild/KMI/runtime inferido desses testes. Auditoria isolada 37406739074 segue no mesmo handle, perfil disabled compilando e enabled na fila no último snapshot.

### Auditoria real da composição de fontes em runner

`.github/workflows/audit-rodin-dma-root-sources.yml` preparado para executar o driver root→DMA numa árvore ACK completa/limpa, com os três repositórios de integração pinados. Fetch de source somente, sem toolchain, Bazel ou build; não substitui auditoria de compilação. Trigger narrow branch/push separado do workflow de kernel, permissions contents:read, pipefail em todos os comandos e logs/evidence preservados mesmo em falha. Upload inclui apenas log, JSON, diff-stat e commits; nenhuma imagem, installer/release ou acesso a device. Não cancela auditoria isolada já em execução.

`validate-dmabuf-root-workflow.rb` passou no Ruby/Psych local: pins, tag object/commit checks, interface do driver, steps/actions allowlist, logs, limites e ausência de comandos build/device. Três negativos rejeitam pin alterado, permissão write e ADB adicionado. Sete unit gates do driver passaram novamente. Execução real do runner ainda por confirmar; integração completa não inferida do YAML nem dos mocks.

### Resultado real: composição root + DMA passou

Actions **37407816068**, head **4f8f9e5aff784bdef7bae7ca5ce3770b83f094b8**, concluiu **success**. Artifacts baixados em `outputs/dma-root-source-audit-37407816068/dma-root-source-audit-1`: log e composition.json conferidos. Root integrator chegou ao marker final com os 26 tracked files/manifest ceb50cf6...; driver só depois aplicou DMA e confirmou pre/postimages/cópias SUSFS. Composição ficou com **30 tracked files**, novo header DMA separado e três fontes SUSFS copiadas hash-pinadas. Manifest final **3b48c383849fa925e3b1a41dd013d668f8f1a4c0e3c179d9f8638a3b94e9c9c9**, agora também pinado no driver para rejeitar drift futuro. memory.c pós-SUSFS antes DMA SHA d44237ad7c613f5c1d3a006dfdd7e82b9d49124de1be3b281e24ae866f16c288; após ambos 8088c5083d4ba15a6d6b6f76f378fbe6e02f885e383da8ab3d6d67eba7b95c95. Quatro commits dos artifacts coincidem com os pins.

Isso comprova execução real da **integração de fontes**, não apenas mock ou patch independente. Não compila e não fecha KMI/producer ownership/unwind, restante dos callbacks/refcounts nem MMU/SMP/hardware. status permanece REVIEW_ONLY_NOT_INSTALLABLE; audit de compilação 37406739074 continua separado no mesmo handle. Nenhum device/flash.

### Build composto DMA/root preparado, dependente dos controles

`.github/workflows/audit-rodin-dma-root-build.yml`: auditoria de compilação separada, sem installer/release/device ou upload de Image. Usa **a mesma concurrency group** do audit ACK, cancel-in-progress=false: aguarda aquele run, não o interrompe e não compila simultaneamente. Antes de source fetch exige status completed/success e head exato dos controles ACK 37406739074/96eaa013... e root sources 37407816068/4f8f9e5...; falha de controle bloqueia antes de compilar. ACK/tag/root pins preservados. Driver real integra root→DMA; depois entram os controles ROM filemap/exports/KMI/certificado e SCM já usados no workflow stock-like. Não altera workflow diário nem adiciona GPUEB/network/governor ao audit.

`prepare-dmabuf-root-fragment.py` combina fragments **hash-pinados** sem alterar nenhuma configuração root; só acrescenta THP=y e DMA=y. Rejects duplicatas, interseção de keys, delta extra, drift e output existente. Quatro unit tests passaram; merged SHA256 07b946c705ba5b814666e029641699acdb924f7abcbfe520731987c77aaa1169. Build gate verifica todas as configurações pedidas no .config real, não apenas KSU y. ELF provider/config auditor, KFENCE/config stock alignment e referência dos 610 módulos/78 assinaturas/import CRCs/certificado embutido integram o gate pós-compile. Aliases de vmlinux/config/Image/symvers só aceitos quando byte-identical. Release banner stock e metadata KSU 33239/v3.3.0 exigidos, fallback rejeitado.

`validate-dmabuf-root-build.rb` passou com quatro negativos: controle adulterado, cancelamento, write permission, etapa ABI removida/device command. Bash -n de todos os blocos e compile dos três Python heredocs passaram. Sete unit gates root e cinco ELF/config gates passaram novamente. Workflow preparado **não é evidência de compilação concluída**; MMU/SMP/hardware, produtor/unwind e restante do lifetime continuam pendentes.

### Devolução da referência de arquivo: fput stock

Fontes ACK pinadas em `outputs/stock-ack-dma-file-lifetime-reference-20261006`: fs/file_table.c SHA1 blob 234284ef72a9a5b22cec70f0d45009b9b686df00/SHA256 1e80b584d85be578964e4f7988e669ef534278c25a5b5eb03565e03754a32519; fs.h/sched.h também verificados por Git blob/SHA256 no commit f7ebe251. `test-dmabuf-stock-file-put.py` executa o corpo ARM64 exato de fput, validando protótipo/layout BTF transitive de file.f_count/f_rcuhead/f_llist, callback_head, task flags e thread_info preempt_count. 280 inputs: referências 1/2/17/18/LONG_MAX, preemption/interrupt masks, kernel thread, sucesso/falha task_work_add e lista delayed vazia/ocupada. Buffer completo de file e argumentos/order comparados com oráculo delimitado; contador sempre decrementa uma vez. Referências restantes retornam sem enqueue; última referência agenda task-work ou delayed fallback. Falha task-work evita leak por fallback; delayed work só agendado quando lista passa a não-vazia. 18 drops adicionais resultam em um único task-work no último drop; zero-ref fput não é input válido. __fput/____fput síncrono proibido no fixture.

Queue/task-work/workqueue bodies modelados; system_wq é contexto runtime privado explícito e delayed_fput_list é BSS **não extraído**. Não executa destruição final nem prova fila/concurrency real. Fixture split-VMA agora executa stock fput sobre o **mesmo file** que recebeu get_file inline: 108 sucessos com file retornam de 18 para os 17 holders originais, sem mudar outros bytes/callbacks nem agendar liberação. Não é close caller real; restante de close/fput final/VM free/RCU e lifetime ainda pendente. 1.152 casos split, quatro boundary/two CFI guards, 108 returns e 280 fput cases passaram. Nenhuma recipe/produção alterada.

### Primeiro resultado de compilação: DMA disabled

Run 37406739074/head 96eaa013...: job **compile (disabled, n) success**, incluindo Check compiled providers. Artifact dma-audit-disabled-1 baixado em `outputs/dma-disabled-build-audit-37406739074`; providers.json exige enabled=n, providers vazio e OFFLINE_BUILD_SHAPE_ONLY. Hash do config conferido independentemente e manifest de overlay idêntico ao canônico local. Gate inclui geometria ARM64/4K/VA39/3levels/split locks e THP. Isso prova build disabled sem os dez DMA functions/quatro counters, não equivalência runtime integral ao stock. Perfil enabled iniciou Fetch pinned ACK; build composto 37408379865 segue pending, aguardando controle completo verde. Nenhum restart/device/flash.

### Close no mesmo objeto criado por split

Fixture split-VMA acrescenta o bloco **delimitado** de exit_mmap 0xffffffc08033b2b4→0xffffffc08033b2fc (72 bytes, SHA256 67980becd27b68fd4f0ea17f5393b8876919bee3b216c69d5cb802f528041345). Não é execução do exit_mmap inteiro: VMA já unmapped/unreachable e registers live-in x22=VMA/x25=dummy ops são precondições explícitas. Ao invés de chamar fput isolado, o bloco stock opera sobre a mesma duplicata/buffer file do split. 216 sequências: 144 close callbacks, 108 stock fput reais e 216 chamadas __vm_area_free modeladas, na ordem close→dummy vm_ops→fput se file→free. Referências retornam de 18 para 17; com file ausente permanecem 17 sem fput. vm_ops ausente permanece NULL; quando close existe, stock instala vma_dummy_vm_ops (144 bytes vazios conferidos no Image). Isso evita reutilizar hooks de um mapping já inconsistente; não é uma alteração DMA nova.

ACK mm/internal.h obtido/verificado no pin f7ebe251: Git blob e66cb4774ccc9e90c2d530f87dae54f30ea227f5, SHA256 0f44c2539968565b7df46d420ef16950ae8d630d6b250b1e7fd97692e8b91d8c, em `outputs/stock-ack-dma-vma-close-reference-20261006`; vma_close tem a mesma substituição de hooks. Fixture agora exige `--close-source` apontando essa referência, além de Image/symbols. BTF também valida assinatura close. Uma terceira CFI guard confirma trap antes de callback/poison/fput/free quando assinatura close é incorreta, preservando count/ops. 1.152 split inputs + 4 boundary guards + 3 CFI guards + 216 close sequências passaram; fput 280 e VMA expand/shrink 48 passaram novamente.

Callback body/free helper, unreachability e estruturas/locks/tree são modelos ou precondições; **não comprova close de produtor real, liberação final de backing buffer, MMU/SMP/concurrency nem ciclo completo do exit_mmap**. Nenhuma receita ou produção modificada; somente validação, referências públicas e documentação.

### Corpo real __vm_area_free no encadeamento

Fixture split/close deixa de substituir __vm_area_free: executa seu corpo ARM64 stock sobre as 216 duplicatas produzidas pelo split, após close/fput. Valida BTF void(VMA*) e anon_name offset 144 (NULL neste conjunto). Dois globals BSS vm_area_cachep/vma_lock_cachep são mapeados como contexto privado explícito, com tokens de cache, após conferir símbolo b/B e ausência de span file-backed; não são dados runtime extraídos do Image. Somente kmem_cache_free é interceptado como fronteira do alocador. 432 liberações: por duplicata, cache lock recebe newsem primeiro; cache VMA recebe new depois, ambos uma vez. Cada token/pointer/order e ausência de duplicate free verificados. Header/body/code fonte ACK kernel/fork.c obtido via allowlist **somente desse arquivo adicional**, não diretório kernel irrestrito: blob 59c01d18581299337f251d3fdfd2a091b3376250, SHA256 36d67fea8bd50ed0ee3416a110d39e3332f81ba81f002ebb9b8ec718f81bc395 no pin f7ebe251, em `outputs/stock-ack-dma-vma-free-reference-20261006`. Fetch negatives continuam rejeitando kernel/Makefile e kernel/sched/core.c.

Novo input obrigatório `--free-source` aponta essa referência, além de --close-source/Image/symbols. 1.152 split inputs, 4 boundary/3 CFI guards, 216 close/__vm_area_free sequências e 108 fput reais passaram; 432 chamadas ao slab modelado. Fonte preserva vma_lock_free antes de kmem_cache_free(VMA). anon_name não-NULL, slab allocator real, VM reachability, exit_mmap inteiro, MMU/SMP e backing buffer lifetime **não comprovados**. Recipes/produção não alteradas.

### Preparação de produtor audit-only e cuidado no unwind

Novo `tools/stock-recovery/runtime-audit/audit-map-contract.h`: preflight **novo**, não recipe Xiaomi, não ligado ao kernel/overlay. Restringe apenas futuro produtor de teste descartável a VA/PA 39-bit, start/end/phys/offset alinhados em 2MiB, buffer não vazio/alinhado, offset+length dentro da alocação sem overflow, shared mapping e destino declarado vazio pelo walker kernel. Não muda semântica stock nem prova empty tables/locks/ownership. `test-dmabuf-audit-map-contract.py` compilou C com -Wall/-Wextra/-Werror + ASan/UBSan: todos os seis rejection reasons e 30.240 combinações contra oráculo separado modulo/subtraction passaram (82 aceitas). Casos zero length, u64 wrap, fim da VA/PA, buffer/offset fora de range, private mapping e PMD não vazio cobertos.

Inspeção do mmap.c ACK pinado revelou requisito importante de ownership: erro de mmap_file vai a unmap_and_free_file_vma, que faz **fput(file)→vm_file=NULL→unmap_region→vm_area_free**, sem vma_close naquele label. Não criar ref driver extra assumindo close automático no erro. O syscall ksys_mmap_pgoff para non-anonymous mantém fget(fd) até vm_mmap_pgoff retornar e só então fput; isso pode proteger alocação file-owned durante unwind, mas relação por source **não é teste runtime** e não se estende automaticamente a callers in-kernel/GPU. README do runtime audit registra requisitos e esse risco. Driver real, guest MMU/SMP, fault injection/unwind completo ainda por implementar/validar. Nenhum acesso ao device ou mudança de produção.

### Produtor descartável: fonte implementada, runtime pendente

`tools/stock-recovery/runtime-audit/recovered-dma-audit.c` implementa produtor
**novo, não Xiaomi e não shipping**: dois misc devices 0600/CAP_SYS_ADMIN, modo
PMD ou PTE fixo por arquivo, alocação própria zeroed order-10/4MiB, release
somente no último file reference. Não oferece read/write/ioctl/PFN arbitrário,
não usa MMIO e não adiciona vm_ops/ref extra que dependeria de close em erro.
Mmap exige shared/non-executable, guarda shift/pgoff, bounds/alignment/VA/PA,
verifica PMDs realmente vazios sob mmap write lock, rejeita PTE table já
alocada e chama o mapper recuperado sem alteração. VM_MAYEXEC removido para
não permitir mprotect posterior executável. Continua necessário provar syscall
fget→partial-map unwind→last file release no guest; fonte não prova lifetime.

Kconfig/Makefile opt-in bool/default n e guards built-in/ARM64/4K/VA39/3-levels
estão separados, não sourced por qualquer kernel/workflow. Não foi compilado
contra ACK nem executado em VM. Seis source-policy testes (mutações negativas
de guards/interfaces/permissões/config/build scope) passaram; não são Kbuild.
Preflight ASan/UBSan passou novamente: 30.240 combinações/82 aceitas.
API headers públicos adicionais obtidos no ACK f7ebe251 com Git-blob/SHA gates,
em outputs/stock-ack-dma-runtime-api-reference-20261006. Sem device/flash.

Actions isolado 37406739074/head 96eaa013: **completed success**, ambos disabled
e enabled. Artifact enabled baixado em outputs/dma-enabled-build-audit-37406739074:
providers contém dez STT_FUNC e quatro counters size8; config SHA256 independente
a958b05da1adae6dbf106a4ede148f7cb040fc855cca30b5255185087bd637ef confere;
overlay-manifest byte-identical ao versionado. vmlinux SHA reportado
e901bdf911bac8d6e0fbc55e9326bec3b5cd809aa62ed4357cacbc71b48460d3; vmlinux
não distribuído neste artifact e esse hash não foi recalculado localmente.
Status permanece OFFLINE_BUILD_SHAPE_ONLY. Composto root 37408379865 ainda
in_progress, step Fetch exact ACK and root integration sources no snapshot.
Build isolado verde não prova KMI composto, produtor real, MMU/SMP ou hardware.

### Integração e Kbuild separados do produtor de VM

`prepare-dmabuf-runtime-audit.py` valida novamente patch/recipes canônicos nos
11 inputs pristine; exige 12 postimages DMA exatos no target e quatro SHA256
de produtor/header/Kconfig/Makefile. Escreve somente seis paths de auditoria
(quatro arquivos novos + append em mm/Kconfig/Makefile). Recusa destination
existente, symlink inclusive parent, drift em inputs e evidência preexistente;
dry-run não escreve no target. Gate cobre estes inputs, não árvore completa
nem callers GPU. Seis testes em fixtures descartáveis passaram: dry-run,
apply/repeat, target drift, reference drift, destination/symlink/evidence.

Workflow novo `audit-rodin-dma-producer.yml` separado: ACK tag/object/commit
exatos, baseline DMA enabled e producer bool=y, Kbuild real LTO none/4K,
config e três objetos audit_fops/devices obrigatórios no ELF. Apenas logs,
config e JSON de evidência são uploaded; sem Image/installer/phone/flash.
Concurrency shared com audits anteriores, cancel=false. Não altera workflow
shipping nem perfil composto root. YAML/Bash de todos os steps e Python do
auditor ELF parseados; source-policy seis testes e integration seis passaram.
Kbuild do produtor e guest runtime continuam pendentes, não declarados verdes.
Headers page_to_phys ARM64 verificados no ACK exato em
outputs/stock-ack-dma-physical-api-reference-20261006; definido em asm/memory.h,
incluído por asm/pgtable.h usado pelo producer. Sem ajuste adivinhado de API.

### Build composto: sucesso de compile/ABI, falha no parser pós-build

Actions 37408379865 terminou **failure**, não verde: compile composto passou;
log registra providers, KFENCE, stock config e referência 610 módulos/78
signatures/3506 kernel-import CRCs/certificado embedded aprovados. Falha seguinte
em settings(config): regex uppercase-only rejeitou CONFIG_FONT_8x16=y
(config artifact linha 7428). Artifact preservado localmente em
outputs/dma-root-build-audit-37408379865, incluindo config/Module.symvers/logs;
Image/vmlinux não distribuídos, logo audit de ROM não foi reexecutado localmente.

Backprop: bug no verificador, não evidência de incompatibilidade DMA nem
config errado. Teste regression test_valid_kconfig_lowercase_symbol falhou no
parser antigo; fix aceita A-Za-z0-9_ para enabled/disabled, mantém duplicate e
malformed rejection. Cinco testes passaram. Config **real** do run falho:
6186 symbols parseados e todas 23 opções pinned root/DMA iguais; KFENCE e
stock-alignment também revalidados localmente. Composed workflow validator Ruby
passou quatro negativos. SPEC proposta para registro §B: parser uppercase-only
rejeita identificador Kconfig válido → aceitar case-preserving + regression;
sem nova §V necessária (bug de grammar no gate), SPEC não alterado sem aprovação.

Produtor compile-only já iniciado pelo push: run 37426751994, head
6e5e182f6fbed564ea13b3f5731add766d5ac9eb, Fetch pinned ACK ativo no snapshot.
Não reiniciado/cancelado. Fix do parser composto será novo run serial; failure
antigo preservado, não relabelado sucesso. Runtime/MMU/SMP/producer real ainda
pendentes.

### Workload de VM e referência isolada do checkout

Produtor run 37426751994 terminou failure antes de Kbuild: canonical validator
em runtime-reference (subpasta do Git checkout) recebeu git apply --numstat
filtrado pelo prefix do repo pai e acusou patch path mismatch. Teste novo
reference_inside_unrelated_git_repository reproduziu antes do fix. Preparador
agora copia os mesmos 11 bytes pristine, recusando symlinks, para Git root
temporário independente; validator canônico/path/hash intacto. Sete testes de
integração passaram após fix; não altera recipe nem producer. Backprop proposta
§B: reference subfolder ≠ Git root → isolated canonical validation + regression;
SPEC não alterado sem aprovação. Build composto 37426905255 confirmado ativo.

`guest-workload.c` fonte de workload real Linux ARM64 para QEMU virt: mmap
shared PMD/PTE, alias/data, rejected mappings, close file com VMAs vivas, fork,
partial unmap filho/pai, shared-write, mremap/mprotect split, non-exec guard,
CPU affinity >=2 e leitor concorrente no alias sobrevivente até teardown final.
Só RAM do produtor e DT técnico QEMU; recusa phone/architecture/page mismatch.
Não foi compilado/executado em Linux neste checkpoint. Falta prova de free final,
ENOMEM parcial, guest init/MMU/SMP completo, full lifetime e stock producer.

Oráculo novo audit-data.h/test_audit_data.c passou host clang -Werror ASan/UBSan:
1024 page corruptions detectadas, offsets/hole-tail/full range. Não é MMU
emulada nem test guest. Workflow separado de source compile Linux/staticARM64
preparado; YAML/Bash parseados, outputs só metadata/checksums/refusal, sem
kernel/flash/runtime-success. Trigger do produtor reduzido aos quatro inputs
reais, evitando recompilar kernel por mudanças futuras no workload userspace.

### Preparação do boot real QEMU e gates de serial

Userspace compile run 37427488820/head bf9907f completed success (native Linux
e static AArch64 workload, x86 refusal); não runtime. Composto 37426905255
Compile composed DMA audit ativo, produtor 37427489007 ainda pending no snapshot.

Novo guest-init.c PID1 mounts somente proc/sysfs, cria dois misc nodes por
sysfs dev exato (major10), executa workload e poweroff. Config real ACK control
tem PL011/console, initrd, ELF, PSCI, SMP, proc/sysfs built-in, mas devtmpfs não;
não presumir devtmpfs. Console5:1 no arquivo RAM, audit nodes não hardcoded.
Init source ainda pending compile. Builder newc determinístico aceita somente
static AArch64 ELF, uid/gid/time0, sete entries fixas/trailer/padding512; recusa
output existente/symlink. Quatro testes decode independente/determinism/ELF
negativos/output preservation passaram.

Runner QEMU quatro CPUs/1GiB, sem nic/disk/monitor/host share, timeout bounded,
config prerequisites/Image magic, serial preservado e fail-closed em markers
faltando/duplicados, kernel warn/BUG/Oops/panic, timeout/nonzero. Tests de policy
e processo mocked não são guest execution. Workflow produtor acrescenta compile
init/workload + archive + boot QEMU no mesmo runner; artifacts restringidos a
logs/config/JSON/versions, excluindo kernel/archive/executáveis. YAML/Bash gates
passaram; nenhuma alegação de VM verde antes de serial real. ENOMEM parcial,
free final e stock producer continuam pending mesmo se workload básico passar.

### Busca ampliada de ativação DMA e novo erro do gate de banner

Stock Image/kallsyms SHA exatos: scanner de B/BL, ADR, ADRP+ADD **adjacente**,
valor absoluto da entry e todas ORR logical-immediate incluindo bit39. Decoders
testados com Capstone: 16.384 encodings logical-immediate e 80 ADR/ADRP signed/
page-boundary casos. Text e inittext file-backed; owners são spans inferidos,
não CFG. Resultado outputs/stock-dma-activation-patterns-20261006.json:
zero branches/endereços/pointers de entry, 1661 ORR masks contendo bit39, nove
exact-bit39; único owner DMA é próprio remap. Outras máscaras incluem valores
canônicos/endereço/vector constants, não presumir vm_flags.

Módulos: referência SHA c89309f2205c70dd87d8b3c3a6c679480582b6e9313573b1f3f894d5bad8146c,
610 rows/574 conteúdos únicos hash-selected, 19.578.718 bytes executable sections.
Scanner read-only ELF/symbol-bounds e ORR em **todo conjunto**, não só GPU18;
nenhum target symbol/literal; 519 masks incluindo bit39; exact-bit39 só
bluetooth.vendor_diag_write e mac80211.sta_set_sinfo. NOBITS não extraído/modelado
como payload. Cross-assembled synthetic ARM64 ELF test passou; scan v2 byte-equal
ao primeiro report em outputs/stock-dma-module-activation-patterns-20261006-v2.json.
Não resolve registradores/loads/lookup dinâmico ou VMA store/caller reachability;
zero patterns ≠ recurso unused, nem prova de ganho.

Userspace init+workload compile run 37428061928/head5985458 completed success;
artifact metadata downloaded outputs/dma-guest-source-37428061928: static ELF,
native PID1/architecture refusal e newc archive1.560.576bytes/SHA
87cdacac4326b8f79383cb32c8c74e4515a2bfdf2de913a70ee592067c37d5bc.
Não guest execution. Produtor/QEMU37428061875 confirmado Fetch pinned ACK ativo.

Composto37426905255 terminou failure após compile/providers/KFENCE/config/
610modules/3506CRCs/certificado/23settings aprovados: banner checker final falhou.
Root cause reproduzido: rawregex double-escaped excluía caracteres literais n/0,
truncando Linux release em 6.6.77-a. Após fix, Image stock real revelou **duas
cópias idênticas** do banner, logo count=1 também incorreto. Novo checker aceita
um conteúdo concreto único, rejeita qualquer versão/sufixo/body divergente e
ignora apenas templates sem versão numérica. Quatro regressions passaram,
incluindo fails-before-fix e actual pinned stock Image. Não relaxa pin/ABI.
Actual candidate banner continua não comprovado; erro anterior não o registrava.
Workflow usa checker separado; validator exige release gate e quinto negativo.
Backprop §B proposta: double escaping/identical aliases → parser tested stock,
V28 já exige release exato; SPEC não editado sem aprovação. Nova auditoria
composta necessária; nenhuma alteração da fonte kernel/SCM para esconder erro.

### Checkpoint — VM básica executada; final backing-free instrumentado, pendente

Run 37428061875/head598545816599ada708c2bedb99acb01971266154:
completed success confirmado no Actions e serial real em
outputs/dma-producer-vm-37428061875/dma-evidence/vm/serial.log.
PMD reader_passes=11, PTE=9; quatro markers de conclusão; sem BUG/WARNING/
Oops/panic. ARM64 QEMU 4 CPUs, RAM-only, sem rede/discos/shares.
Image SHA59166ae44ce6cc8bc006b909569a19bc010f71ac8dc22a4ad8fdab34b4691738;
initramfs SHA87cdacac4326b8f79383cb32c8c74e4515a2bfdf2de913a70ee592067c37d5bc.
Prova mmap/fork/move/split/alias/reader no workload básico; não prova ENOMEM,
final backing-free, produtor Xiaomi ou hardware completo.

Run composto 37429423148/headc96c1a5e76ef1855e4932b0bcd497302f85401a7:
completed success; logs de providers/610module entries/3506CRCs/78signed modules/
certificado/23settings/release-banner gate aprovados. Compile/ABI apenas,
não runtime KSU/SUSFS, não instalador/hardware.

Próximo gate: produtor audit-only atribui ID por allocation bem-sucedida e
registra RELEASE **após** __free_pages e kfree, sem ler storage liberado.
Guest marca imediatamente antes do último munmap. Runner exige dois IDs únicos,
um por mode, release único correspondente após LAST_UNMAP e antes CASE_PASS;
eventos ausentes/duplicados/malformados/antecipados/tardios falham fechado.
Fonte/pin/testes alterados; novo runtime ainda pendente. Mocks do parser não
contam como VM execution. Nenhuma mudança do overlay instalável/ABI/interfaces;
nenhum flash/celular. T20 permanece incompleta.

### Checkpoint — preparação determinística de partial ENOMEM, não executada

Enquanto run37492696088/head4a459b23a63ebbfe64a8f131e519100a266d7dca
permanece Fetch pinned ACK/in_progress, preparados dois sites audit-only:
antes pte_alloc_one no path PMD e antes pte_alloc_map_lock no path PTE,
somente dentro de dmabuf_huge_remap_pfn_range. Gerador exige SHA do
mm/huge_memory.c pós-overlay e preserva fora da função byte-for-byte;
CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT guarda declaração e ambas as falhas.
Não usa falha global de page allocator, não muda recipe/manifest shipping.
Código gerado separado: outputs/stock-dma-fault-sites-20261006-v1.

Novo audit-fault-plan.h: one-shot ordinal1/2, task+mm tokens exigidos,
foreign task/mm não consome contador, estado serializado pelo caller.
Host clang -Werror + ASan/UBSan passou; quatro testes do gerador passaram
(drift/reaplicação/symlink/evidence-preservation/reversão exata dos sites).
Prova somente seleção/preparação. Callback real/serialization no produtor,
guest failed-mmap+retry assertions e partial-unwind runtime ainda pendentes.
Não ligado a nenhum workflow/kernel; generated file **não compilável como
audit completo sem callback** e não é candidato instalável. Próximo passo:
armar ordinal2 em task atual, confirmar primeiro bloco publicado, ENOMEM
propagado, syscall remove todas PTE/PMD parciais, retry limpo e final free.
Stock producer activation e full MMU/lifecycle/hardware continuam abertos.

### Checkpoint — partial ENOMEM ligado ao produtor; novo runtime pendente

Produtor agora inclui callback built-in não exportado, mutex só da auditoria,
task/mm-scoped one-shot ordinal2 e reset ao fim do remap. Duas devices fault
0600 adicionais, CAP_SYS_ADMIN, sem ioctl/read/write/PFN interface. Registro de
quatro devices tem unwind inverso em cada falha. Primeira chamada válida fault
consome arm; retries e devices normais não injetam. Map counter deve aumentar
exatamente1 antes da segunda alocação; count errado emite fail marker.
Além do contador, callback verifica a tabela real sob mmap write lock:
PMD present/huge com PFN exato ou todos512 PTEs present/special/PFNs contíguos
do primeiro2MiB. Evita confundir incremento com pmd_set_huge bem-sucedido
(stock ignora esse return). Serial exige table=1; faltante/0 falha fechado.
Isso injeta o **resultado da falha no call site**, não falha global do allocator.

Guest: mmap retorna ENOMEM, mincore retorna ENOMEM, mesma VA aceita
MAP_FIXED_NOREPLACE+preflight sem tabelas remanescentes, dados íntegros;
depois repete workload completo PMD/PTE incluindo close/fork/partial-unmap/
reader/move/mprotect/cross-CPU/final-unmap. Runner exige quatro allocations/
releases únicas e duas sequências alloc→published1/fault→return(-12,fired1)
→same-address retry→last-unmap→release→case-pass→guest-pass→PID1-pass.
Mocks passam negativos de IDs/mode/ordinal/count/result/order/duplicate;
não são runtime evidence.

Run37492696088/head4a459b2 completed **failure na compilação**, não executou VM.
Root cause: AUDIT_BYTES promove ULL por DMA_AUDIT_BLOCK_BYTES=1ULL<<21,
mas novo log usava %lu. Corrigido cast explícito unsigned long; novo teste
compila as cinco expressões reais de log com clang format/Werror; remove-cast
e wrong-ID-format negativos falham. Inicial fixture continha variável não usada;
removida sem desabilitar warnings. Artefato de falha preservado em
outputs/dma-producer-failed-37492696088. Backprop §B proposta: log-varargs type
promotion → compiled expression regression; SPEC não modificado sem aprovação.

Sete testes integração, oito source-policy, oito runner, quatro generator,
quatro initramfs, três log-format e ASan/UBSan selector passaram localmente.
Shipping recipe/hash/interface intocados. Audit huge_memory substitution e
five source pins só no preparer da VM. Novo Actions/actual ENOMEM/unwind/free
ainda pendente; accounting de todos failure sites, ativação real Xiaomi,
runtime composto e hardware continuam obrigatórios. T20 permanece ~.

### Checkpoint — endereço ADRP/ADD não adjacente coberto, rota ainda aberta

Scanner stock agora segue ADRP até ADD imediato64 em janela linear de oito
instruções, sem cruzar símbolo, branch/call/return/trap, decode desconhecido,
write do X/W correspondente (incl. FP/LR aliases e load/store writeback).
Register31 descartado. Capstone register-write/control detalhe aplicado só à
janela; módulo scanner que usa ORR mantém dependência lazy, seu ELF test passou.
Nenhuma reaching-state inventada através de branch/copy/load; candidate ≠ CFG.

Oito decoder tests passaram: nonadjacent STR-read permitido, X/W/FP/LR writes,
load e pre-index/pair-store writeback recusados, controls/trap/boundary/window8,
ADD in-place stop, shifts/encodings contra Capstone, 16.384 logical immediates,
80 ADR signed-boundary cases. Initial failures revelaram UDF decodificado mas
sem grupo de trap (stop explícito) e ADD SP,#0 alias MOV com dois operandos
(fixture agora reconhece sem presumir terceiro operand). Backprop §B proposta:
decoder groups/alias shape ≠ semântica completa; negativos mantidos; SPEC intacto.

Actual exact-stock scan concluído em outputs/stock-dma-activation-patterns-
20261006-v3.json: 0direct entrybranches, 0entry address patterns (agora inclui
nonadjacent), 0absolute entryvalues; mesmos1661 ORR masks incluindo bit39.
Não fecha loaded/register-copy/relocation/dynamic/entry-offset routes nem
store de VMA/reachability; resultado negativo não autoriza dizer unused.

Guest compile run37494587573/head14c66587c2dae3ccedf2a0f06eb8f5849a96534e
completed success, artifact real lido em outputs/dma-guest-source-37494587573:
static AArch64 ELF e initramfs1561088bytes/SHA
1a5a5473b8411c0ef27e2fe25100b32f4c35f0779d4f5dc1b28bd5912f6142ed.
Esse job não executa VM. Produtor37494587692 confirmado Compile audit kernel
in_progress após source/integration/format/selector gates aprovados.
Runtime partial-ENOMEM/free, original activation e hardware continuam pendentes.

### Checkpoint — ENOMEM/retry/final-free reais aprovados; alternativas classificadas

Run37494587692/head14c66587c2dae3ccedf2a0f06eb8f5849a96534e completed
success, incluindo Compile/ELF-provider/QEMU. Artifact baixado em
outputs/dma-producer-vm-37494587692/dma-producer-compile-5/dma-evidence.
Config/serial reais revalidados pelo checker local atual. Image SHA
cb17378ae79198f7ce2681c4174191dd74790af4a1178ad25cefaaba44aee611;
initramfs SHA1a5a5473b8411c0ef27e2fe25100b32f4c35f0779d4f5dc1b28bd5912f6142ed.
IDs1..4 alloc→last-unmap→release→case-pass exatamente uma vez. Readers
11/9/10/11 passes. Fault IDs3(PMD)/4(PTE): ordinal2,published1,table1,
result=-12,fired1; guest same-address retry=1 e workload completo aprovados.
Sem BUG/WARNING/Oops/panic. Release marker após __free_pages+kfree reais.
Prova esses casos, não every failure site/accounting/SMP/producer/hardware.
Runtime é ACK puro sem KSU/SUSFS; composto continua compile/ABI apenas.

Busca interior agora cobre todo span inferido de1200bytes da remap, não só
entry. Actual scan encontrou18 branches:17 locais,1 externo aparente em
0xffffffc0803bccdc→0xffffffc0803bbb18. Não é caller da função vizinha:
BTF stock alt_instr validado12bytes, campos orig_offset/alt_offset s32,
cpucap16,orig_len8,alt_len8; 29.849 entradas extraídas de __alt_instructions.
Entry0xffffffc081d3e178 associa replacement0xffffffc0803bccdc, original
0xffffffc0803bbb14,cap53,len4/4. Branch retorna original+4; é alternative
replacement do próprio remap, owner por next-symbol seria falso positivo.
Analisador agora registra contexto de alternativas sem presumir CPU patch
selecionado. Report outputs/stock-dma-activation-patterns-20261006-v5.json:
0external-nonalternative branches;0entry refs;1661 ORR masks bit39.
Onze decoder tests e módulo ELF test passaram, incluindo signed PREL offsets,
BTF drift, interior/local/bounds. Nenhum input stock alterado/alternativa aplicada.

Ainda obrigatório: todos failures/accounting/complete MMU/lifetimes, registro/
callback/ativação real Xiaomi, runtime composto e hardware. Installer bloqueado,
nenhum flash; T20 continua ~. Evidência real não substituída por mocks.

### Checkpoint — contabilidade de tabelas pós-ENOMEM instrumentada; runtime pendente

ACK pin include/linux/mm.h usa mm_pgtables_bytes() e mm_inc/dec_nr_ptes/
nr_pmds sobre atomic_long pgtables_bytes. Não existem mm_nr_ptes/mm_nr_pmds
getters nessa revisão. Novo produtor lê total antes do remap fault, após
primeiro bloco publicado e na entrada do retry na mesma task/mm. Exige
partial-before=4096 ou8192 (PTE, possível PMD) e retry=before. Context tokens
comparados, não dereferenciados; mutex de auditoria serializa remaps. No guest
esse intervalo antecede fork/reader, sem mutação concorrente de outras VMAs.
Não prova leak-free universal a partir do total: preflight/table checks e
sequência controlada continuam necessários; todas outras falhas permanecem abertas.

Runner exige dois DMA_AUDIT_UNWIND IDs/modes e ordem fault_return→unwind
→guest_retry; leak/underflow/delta impossível/wrongid/context/order/dup falham.
MMU=y agora gate explícito. Três log-format tests compilam oito expressões
reais; nove source-policy/nove runner/sete integration e selector/generated-site
testes passaram localmente. Pin produtor atualizado, overlay shipping intacto.
Run37494587692 continua prova dos gates antigos, **não** deste novo accounting.
Nova execução real necessária; T20 permanece ~, nenhum flash/dispositivo.

### Checkpoint — accounting real aprovado; seletor DMA core recuperado

Run37499127549, commit378e89a62283bc7ad79daab684003373fc96fa9a:
compile/providers/QEMU success. Artefato dma-producer-compile-6 extraído em
outputs/dma-producer-vm-37499127549/dma-producer-compile-6/dma-evidence.
Config e serial reais revalidados pelo runner atual. Ambos modos registraram
before32768→partial36864→retry32768; failure=null. ImageSHA
85b47c0b4b19e57188881645b7e8b53b04ffe7962f7ef6850bb4e177c139f0e4;
initramfsSHA1a5a5473b8411c0ef27e2fe25100b32f4c35f0779d4f5dc1b28bd5912f6142ed.
Prova cobre selected second-allocation failure/unwind, não todos allocators.

Nova lacuna real: stock dma_buf_fops+152 contém pointer0xffffffc0803bca3c
para dma_buf_hugetlb_get_unmapped_area. BTF file_operations size264 confirma
offset/prototype; mmap+88→dma_buf_mmap_internal, release+120→dma_buf_file_release.
ACK core pinnedSHA81c6e69759857e3ba198f2b45b5b5634721119db0e181ed0fd6454f3cdc8fa1c
nunca registra get_unmapped_area. Callback faltava no overlay original.
extract-dmabuf-address-selector.py valida hashes/BTF/raw pointers; report
outputs/stock-dma-address-selector-20261006-v1.json. Prefix672bytes termina
em __stack_chk_fail; inferred span800 ≠ função ELF, alternatives não aplicadas.

Reconstruction dmabuf_huge_address.recovered.c: mask0 abaixo64KiB,
mask0xffff a partir64KiB, mask0x1fffff a partir2MiB; hint arredonda
correspondentemente, MAP_FIXED mantém endereço bruto após length check.
Topdown low=max(PAGE_SIZE,mmap_min_addr); fallback usa mm->mmap_base,
não TASK_UNMAPPED_BASE genérico. Prev usa vm_end sem grow-up gap; preserve
stock behavior, não alteração silenciosa. Compat bit22/tasksize0xfffff000
e high-address arithmetic mantidos. pgoff/file ignorados pelo seletor stock.

4050 differential cases passaram contra ARM64 exato: hint2516,
allocator2368, fallback402. BTF task/mm/VMA/info offsets verificados;
mmap_min_addr BSS modelado explicitamente. Lookup/allocator bodies modelados:
prova outputs/helper arguments, não Maple-tree/allocator/MMU/SMP/lifetimes.
RecipeSHA12bd968b8d17db819557094d43db1990fef0b50c3bf694e0fda398d0997c6878.

prepare-dmabuf-address-overlay.py gera extensão de um arquivo, guarded por
CONFIG_XIAOMI_DMABUF_HUGETLB default-off do overlay base, sem editar inputs.
Patch-roundtrip/disabled-byte-preservation/anchors/provider-pointer tests
passaram. Extensão outputs/stock-dma-address-overlay-20261006-v1 permanece
REVIEW_ONLY_NOT_INSTALLABLE. Audit workflow passa a compilar extensão e
verificar pointer no vmlinux; nova execução ainda necessária. Guest existente
usa misc producer, portanto runtime dele não prova rota VFS DMA-BUF registrada.

Ainda obrigatório: enabled/disabled Kbuild da extensão, real DMA-BUF exporter
workload/core→ops->mmap, restantes failures/accounting/full lifecycle/MMU/SMP,
root-composed runtime e hardware. Shipping overlay intacto, sem flash/device;
T20 permanece ~. Este checkpoint supera apenas pendências antigas específicas.

### Checkpoint — exportador DMA-BUF real preparado; runtime ainda pendente

Produtor misc antigo não exercita dma_buf_fops nem dma_buf_ops. Novo
recovered-dma-export-audit.c usa dma_buf_export/dma_buf_fd e owned4MiB
zerados; factory0600 CAP_SYS_ADMIN em open/ioctl, dois fixed _IO selectors
PMD/PTE + live-counter-only query. Rejeita arg!=0/unknown command; max8bufs.
Sem user pointer/PFN/tamanho/MMIO/read/write interface. SG map/unmap usa
owned pages + DMA API real, não valida anexação/DMA físico nesta carga CPU.
Export failure libera pages/struct/count; fd failure usa dma_buf_put;
release log e live decrement ocorrem depois de ambos frees. Não shipping.

Plain remap do exportador compartilha audit_fault_mutex com produtor antigo:
instrumentação ENOMEM task/mm scoped não pode vazar para outro remap.
Kconfig audit permanece built-in/default-n e agora depende DMA_SHARED_BUFFER.
Source integrator pinna sete inputs; dez paths totais no disposable tree,
overlay de produção/base segue intacto. Symbols audit novos namespaced.

Guest ampliado: real DMA-BUF 4K/64K/2M/4M mmaps, hints0x20001000/0x40001000
devem retornar endereços arredondados exatos (não alinhamento acidental),
CLOEXEC, core extent rejection, zeroed RAM/full-data alias checks,
close-fd retention, fork/shared write/child partial unmap, mremap/SMP,
querylive1 até lastunmap e live0 após real frees, wait limitado500ms.
Small maps usam generic remap_pfn_range;2M/4M mapper recuperado.

Runner agora exige oito exporter mmap/align events e duas alloc/release
identities com last-unmap ordering; missing/wrong-id/mask/hint/result/live/order
falham. Não aplicar novo runner como prova a serial antigo sem esses eventos.
Source/format/fixture/integration/mock gates passaram; novo Kbuild e QEMU
continuam pendentes. Run37511000979 pertence ao commit anterior07f49af,
não contém este exportador. Nenhum dispositivo/flash; T20 continua ~.

Revisão/backprop local: bit-test direto de fcntl(F_GETFD) aceitaria -1 como
CLOEXEC porque todos bits ligados. Guest agora rejeita fd_flags<0 antes do
bit-test; regressão C compilada executa -1/0/FD_CLOEXEC. Classe(a) bug no
próprio novo teste, não ABI/spec alterados; proposta §B futura: false-CLOEXEC
pass por unchecked syscall return, sob V35 evidence-not-inferred. SPEC não
amendada sem aprovação; registro/correção local não pausa implementação.

### Checkpoint — header integration failure identificado e corrigido

Run37511000979 (07f49af) falhou no Kbuild:
drivers/dma-buf/dma-buf.c:583:14 undeclared MAP_FIXED. VM/providers skipped;
nunca tratar como runtime pass. Fixture diferencial define MAP_FIXED para
provar corpo/routing, portanto não detecta include ausente no translation unit
real. Classe(a) integração/adaptador errado, não falha da equivalência ARM64.

Address overlay prefix agora inclui linux/mman.h dentro do feature guard,
antes do corpo recuperado. Nova regressão falhou antes e passou após fix;
disabled branch continua removendo include/callback, sem delta funcional.
Recipe bytes/semântica4050cases não alterados; patch/manifest extension novos.
Run37512915333 (54c6afd) cancelamento solicitado por herdar mesmo bug;
guest-source37512914935 independente, não cancelado. Não reiniciar somente
por polling timeout; verificar estado terminal antes de próxima execução.
Proposta §B futura: semantic fixture ≠ integration-header compile proof,
sob V35/V39; SPEC não alterada silenciosamente.

### Checkpoint — cold-PUD runtime panic rastreado, predicate corrigido

Run37513469218 (e5f1016): Kbuild/providers/address-registration pass; QEMU
failure. Artifact dma-producer-compile-9 preservado em
outputs/dma-export-vm-37513469218. Serial real: quatro misc/lifetime/unwind
casos passaram; DMA-BUF4K/64K incluindo hint passaram. Primeiro DMA-BUF2M
hint0x40001000→0x40200000 panic em _raw_spin_lock, lr remap+0x33c,
pointer inválido0xffffffffff000028. Não é pass de integração.
ImageSHA940e65a369cc1e47a548d9c98244e66149bc4d1a4fcd1a53088359aa75b12ace;
initramfsSHA75359f06535410ea50acc693399e74cd3b9b0605a177d9819f54ece05737a4c5.
Guest-source37512914935 completou success; isso prova compilação, não runtime.

Causa comprovada no código: recovered mapper usava pgd_none(*pgd) antes de
__pmd_alloc. ACK nop4d pgd_none retorna0; nopud p4d_none retorna0.
ARM64 pud_none testa !pud_val. Nesse geometry3-level, primeira entrada real
é PUD alias do slot pgd. Stock0xffffffc0803bb9f0 LDR +9f4 CBZ testa entry
zero e chama __pmd_alloc em0xffffffc0803bba34. C antigo pulava allocator
quando slot vazio; decode__va(0) → pointer inválido ao buscar PMD lock.
Mocks antigos pgd_none=!raw mascaravam diferença; VM antiga usava PGD já
populado. Novo endereço baixo revelou delta, não hazard intencional stock.

Fix: pud_none(*(pud_t *)pgd), sem alterar condição stock ou export/ABI.
PMD fixture agora define folded pgd_none=0 e real pud_none. 216PMD+360PTE
exact ARM64 cases passaram. Nova regressão compila helper definitions dos
três headers ACK imutáveis e condição real C: zero/nonzero + allocator failure;
old-predicate variant falha. Prova branch/helper semantics, não allocator/MMU.
Headers em outputs/stock-ack-dma-folded-reference-20261006.

Overlay regenerado em outputs/stock-dmabuf-overlay-20261006-v5 e canonical
review patch/manifest atualizados; recipe SHA8c037458747db7632df2f2a02c5fb816958418dd097b6e303c5ef5fd0e0e79fb.
Fault-site tests agora geram input do candidate atual pin-verificado, não
artefato v4 histórico. Runner prioriza Oops/panic antes de missing marker.
Proposta §B futura/V39: folded predicates ! native-definition regressions;
fixture routing ≠ native-helper integration. SPEC não editada sem aprovação.
Nova VM real obrigatória, remaining failures/complete lifecycle/KMI/root/
hardware continuam pendentes; não shipping/flash, T20 continua ~.

### Checkpoint — site-aware fault selector e cold-PUD injection scaffold

Local, sem novo push enquanto VM37519394415 continua pending/jobs=[].
Header separa PMD_TABLE de LEAF antes de avançar ordinal; owner/mm tokens,
one-shot e legacy wrappers LEAF preservados. ASan/UBSan passou para ambos
sites×ordinals1/2, wrong site/task/mm, invalid arm e reset.
Preparer agora gera três sites: cold PUD antes de __pmd_alloc, deposited
pte_alloc_one e pte_alloc_map_lock. Callback novo builtin audit-only;
PMD_TABLE permanece dormant: guest ainda arma só LEAF ordinal2.
Não alegar cobertura de falha PMD_TABLE/first-leaf em runtime.

Teste compila branch gerado exato com auditoria enabled/disabled: cold/warm,
callback failure e allocator failure; disabled ignora callback e preserva
allocator routing. São contadores de helpers, não prova MMU/allocator nativo.
Fonte externa ao mapper preservada e removendo substituições recupera bytes
originais. Pins header/producer atualizados; ELF gate exige callback novo.
Testes locais: fault selector1, sites5, integration7, source9, formats3,
exporter6, build gates5. Um comando tentou nome inexistente audit-source.py;
erro mecânico de invocação, corrigido para runtime-producer-source.py9pass,
não foi falha de código ou resultado de kernel. V35/V39 continuam aplicados.
T20 permanece ~; guest failures restantes, KMI/root/SMP/hardware pendentes.

### Checkpoint — first-leaf guest e gates locais implementados

T20/V35/V39, sem flash/shipping; commit anterior2d7418f local, não enviado
enquanto VM37519394415 pending/jobs=[] no head0ab92e4. Novo produtor adiciona
first-pmd/first-pte root0600/CAP_SYS_ADMIN com buffer próprio4M por open.
Primeiro mmap válido arma LEAF ordinal1; dispositivos fault-* continuam2.
Callback verifica publicação0/table0 para1, publicação1/table1 para2.
Guest usa ENOMEM/mincore no VMA, retry NOREPLACE mesmoVA, full data e depois
mesmo alias/fork/move/protect/unmap/reader/SMP workload dos outros casos.
Accounting1 aceita somente delta0/4K;2 somente4K/8K, retry exact baseline.
Não presumir unwind nativo: esses novos casos ainda precisam VM real.

Parser exige seis IDs allocation/release, quatro falhas por ID/mode/ordinal,
estado publicado exato, accounting+retry+lastunmap/release ordering.
Negativas cobrem first-leaf com publicação falsa, ID/mode/ordinal trocado,
leak/underflow/baseline incorreto e markers ausentes. Histórico4casos não
passa gate6 atual: não reclassificar artifacts antigos como pass novo.
Novo teste compila audit_init real em hostASan/UBSan e falha cada um dos seis
misc_register: deregister reverse apenas providers previamente registrados,
exatamente uma vez; sucesso registra todos sem deregister. Não Kbuild proof.
PMD_TABLE callback permanece dormant; guest cold-PUD failure ainda pendente.

### Checkpoint — cold-PUD guest e eight-buffer gates implementados

T20/V35/V39. VM37519394415 segue pending/jobs=[] no head0ab92e4;
audit37519394148 disabled Kbuild/providers success, enabled compilando.
Novos table-pmd/table-pte, root0600/CAP_SYS_ADMIN, arma site PMD_TABLE1.
Guest verifica VA slot inteiro1GiB via PROT_NONE/NO_REPLACE, unmap e usa
4/6GiB para mmap/retry. Nenhum MAP_FIXED clobber durante reserva.
Kernel exige PUD real vazio antes de armar; callback relê cold, publicação0,
table0 e contabilização0delta; retry deve manter baseline exato.
Isso injeta o resultado de falha no site exato, não prova allocator nativo.
Guest continua mincore semVMA/retryNO_REPLACE/full-data e toda lifecycle.

Parser exige oito IDs finais e seis falhas; PMD_TABLE distinta de LEAF,
cold reservation order, cold1, zero temporary accounting; negativas cobrem
wrongmode/ID/ordinal, publicação/table/cold falsa, leaks e markers ausentes.
Init hostfailure matrix agora cobre oito misc_register unwind em reverso.
Formats strictClang compila dez logs reais. Source policy cruza inventários
produtor/guest/init, não deixa novo device sem caso/nó.
Novo runtime não executado: não reclassificar históricos4/6 casos como pass8.
Ainda falta later-PGD allocation failure após primeira publicação, todos
MMU/TLB/SMP/lifetime e stockGPU/root/KMI/hardware gates. T20 permanece ~.

### Checkpoint — native root-boundary regression e crossing guest

T20/V35/V39, sem nova recipe/canonical patch mudança. Verificado no ACK
include/linux/pgtable.h SHA bdfc3c9f86b18719f0bec51cfb5174918a81285da4eefefe9afd3880fac164fc:
pgd_addr_end usa PGDIR boundary, não é folded constant-end. nop4d sobrescreve
p4d_addr_end, nopud sobrescreve pud_addr_end. Hipótese de macro PGD errado
refutada: mapper já usa pgd_addr_end correto, nenhuma correção fictícia.
Novo teste compila macro nativo exato + expressão real recipe, perfil explícito
4K/VA39/3levels, spans dentro/cross1GiB/highVA e rounded-boundary wrap.
Regressão trocando para p4d_addr_end falha; folded suite4tests pass.
Isso prova aritmética, não MMU/PTE/PMD allocation/hardware.

Guest8cases adiciona alias4M em16GiB-2M, após reservar2slots inteiros via
PROT_NONE/NO_REPLACE e remover reserva; nenhuma thread existe nesse ponto.
Verifica cada palavra nos dois lados e unmap antes de close(fd)/fork/readers.
Parser exige8cross markers com bytes4M/root_slots2/data_verified1, entre
allocation e lastunmap; nos casos fault, após accounting+retry marker.
Negativas para missing/duplicate/wrongmode/one-slot/no-data/wrongsize/ordem.
VM37519394415 ainda pending/jobs=[]; novo guest não executado remotamente.
Todos gates full-DMA/stockproducer/root/KMI/hardware continuam pendentes;
T20 permanece ~, não instalar nem alegar cross-boundary runtime pass.

### Checkpoint — local-first; second-PGD failure conjunto fechado localmente

Instrução atual do usuário: terminar implementação/revisão/testes locais antes
de novo push/Actions. Não disparar build por cada correção. Não interpretar
code/local-test completion como runtime/MMU/hardware pass. Runs já existentes
não foram cancelados/reiniciados; nenhum novo push/dispatch nesta etapa.

table-cross-pmd/table-cross-pte implementados, root0600/CAP_SYS_ADMIN.
Guest reserva2GiB sem clobber e usa8/12GiB+1GiB-2MiB para cruzar dois slots.
Preflight exige ambos PUDs vazios, size4M e startmod1GiB=1GiB-2M.
Site PMD_TABLE ordinal2: callback relê segundo PUD vazio e primeiro bloco
publicado com PFNs próprios; publication1/table1/cold1. Accounting temporário
exato8K, baseline restaurada antes de retry. ACK mm/memory.c __pmd_alloc
incrementa nr_pmds e mapper PMD incrementa nr_ptes; PTE path cria uma tabela.
Isso fundamenta o gate8K, não prova o unwind nativo até VM executar.

Parser/hostfixtures/init/sourceinventory/pin atualizados como conjunto para10
buffers,8falhas,10crossaliases e quatro cold-range markers. Negativas focadas
em second-PGD publication/ordinal/ID/mode/cold, accounting0/4K/12K/leak,
reserva de tamanho errado. Init failure matrix cobre todos10register sites.
T20/V35/V39: código e locais avançaram; stockproducer activation e revisão
transitiva restante continuam obrigatórios antes de chamar local completo.

### Checkpoint — proteção NULL somente na integração (V35,V39)

Receita stock `dmabuf_huge_wrappers.recovered.c` permanece byte-idêntica/pinada.
Gerador adiciona `if (!next) return` antes de ler `next->vm_start`; alteração
explícita em `safety_deviations`, validador rejeita omissão desse metadado.
Não tratar código adaptado como stock exato no caminho NULL.

Teste nativo ASan/UBSan reproduz NULL dereference do stock em processo isolado;
adaptação passa lookup NULL, VMA NULL/adj0 e comparação de traces definidos.
3.000 routes ARM64 da receita original passam; cinco testes do gerador e seis
do validador passam. Bateria local de fault/preflight/folded/runtime-source/
exporter/parser/init/guest-data/root passa. Não prova VM/MMU/SMP/hardware.

Backprop proposto, ainda não aplicado à SPEC: B46 — lookup NULL dereferenciado;
V41 — integração guarda lookup antes de dereferenciar; desvio explícito,
receita stock imutável e teste sanitizer. Requer aprovação da alteração da SPEC.

Inspeção pontual stock: `dma_buf_mmap` e `dma_buf_mmap_internal` chamam
`dma_buf_ops.mmap` indiretamente (offset0x60); `remap_pfn_range` chama
`remap_pfn_range_notrack`, sem redirecionar para mapper Xiaomi. Mapper especial
não exportado. Isso refuta redirecionamento automático nessas funções, não
prova feature inativa nem fecha todos os exportadores/dynamic lookups.

### Checkpoint — composição MM/core e rota real Mali/heap

`prepare-dmabuf-combined-overlay.py`: gera base e callback em diretório
temporário; valida identidades/escopos disjuntos/hash antes de criar resultado.
Patch único sete arquivos, status REVIEW_ONLY_NOT_INSTALLABLE; preserva pending
e safety_deviations. Resultado local: outputs/stock-dmabuf-combined-20261006-v1.
Três testes usam fontes ACK reais: round-trip, disabled idêntico, exports
inalterados, callback único, guard NULL; drift core e output existente abortam
sem substituir arquivo. Não muda workflow/config nem ativa produtor stock.

`extract-dmabuf-exporter-routing.py`: seleciona três identidades exatas dentro
do inventário pinado610/78; rejeita ELF não ARM64 ET_REL, valida opcode de
CALL26/JUMP26, resolve registro ABS64 em objetos, não altera módulos.
Teste ELF cross-assembled valida bounds, tail-call, offsets e registro.
Resultado: outputs/stock-dma-exporter-routing-20261006.json.

Mali `kbase_fops.mmap` offset88 → kbase_mmap → kbase_context_mmap;
reloc CALL26 caller+1568 → dma_buf_mmap. Em system_heap, objetos
mtk_mm_heap_buf_ops/system_heap_buf_ops/mtk_slc_heap_buf_ops registram mmap
offset96 → mtk_mm_heap_mmap/system_heap_mmap. CALL26 respectivos+236/+188
→ remap_pfn_range, não mapper especial. mtk_sec_heap não possui função mmap
nomeada nesta tabela; ausência de nome não prova ausência de qualquer rota.

Rotas ELF específicas ≠ todas branches alcançáveis/runtime. GPU MMU e CPU VMA
distintos. Não inserir roteamento artificial nesses callbacks e chamá-lo stock.
Investigar exportadores/lookup indireto restantes; full activation segue aberto.

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
