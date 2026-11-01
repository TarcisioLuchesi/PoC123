# Icegram Collect 1.3.21: `review_url` sem escape no aviso de avaliação

> Análise do código da versão 1.3.21. O sink permite injetar marcação HTML quando a requisição traz um nonce administrativo válido. Não foi demonstrado um caminho de exploração por visitante, Subscriber ou outro usuário sem `manage_options`.

## Resumo

O aviso de avaliação do Icegram Collect recebe `review_url` pela query string e o imprime diretamente dentro do atributo `content` de uma tag `<meta http-equiv="refresh">`. Aspas no valor podem encerrar o atributo e fazer o navegador interpretar novas tags. O problema de escape existe no código; o fluxo normal exige uma tela administrativa específica, a capacidade `manage_options`, pelo menos dois leads publicados e o nonce `review` do próprio usuário. A análise disponível não demonstra que um atacante externo consiga fornecer uma URL maliciosa com o nonce de um administrador.

Examinei o pacote identificado como versão 1.3.21 no cabeçalho de `icegram-rainmaker.php` e em `readme.txt`. Os trechos abaixo são desse pacote. Esta é uma análise estática: não há registro de execução do payload no navegador, nem histórico verificado para definir a primeira versão afetada ou uma versão corrigida.

## 1. Do construtor ao hook

Em `lite/classes/class-icegram-rainmaker.php:85-96`, `Rainmaker` carrega a classe de feedback e a instancia com o prefixo `ig_rm`:

~~~php
$ig_feedback_class = 'IG_Feedback_V_' . str_replace( '.', '_', $feedback_version );
$ig_rm_feedback    = new $ig_feedback_class( 'Rainmaker', 'icegram-rainmaker', 'ig_rm', 'rmfree.', false );
~~~

O construtor de `IG_Feedback_V_1_2_5` primeiro consulta `can_show_feedback_widget()`. Se o recurso estiver habilitado para o ambiente, registra o aviso em `admin_notices` (`lite/classes/feedback/class-ig-feedback.php:106-121`):

~~~php
if ( ! $this->can_show_feedback_widget() ) {
    return;
}
add_action( 'admin_notices', array( &$this, 'show_review_notice' ) );
~~~

Assim, `show_review_notice()` é chamado durante a renderização de avisos de páginas administrativas. Essa ligação pelo hook é o ponto de entrada do fluxo de leitura de `review_url`.

## 2. Quem alcança o aviso

`show_review_notice()` aplica o filtro `ig_rm_can_ask_user_for_review` antes de processar os parâmetros da URL (`class-ig-feedback.php:192-194`). A implementação em `lite/classes/feedback.php:78-93` exige uma tela do Icegram Collect, `manage_options` e ao menos dois leads publicados:

~~~php
$screen = get_current_screen();
if ( ! in_array( $screen->id, array( 'edit-rainmaker_form', 'rainmaker_form', 'edit-rainmaker_lead', 'rainmaker_form_page_icegram-rainmaker-support', 'rainmaker_form_page_icegram-rainmaker-upgrade' ), true ) ) {
    return false;
}
if ( ! current_user_can( 'manage_options' ) ) {
    return false;
}
$total_rm_leads         = wp_count_posts( 'rainmaker_lead' );
$total_rm_leads_publish = $total_rm_leads->publish;
if ( $total_rm_leads_publish < 2 ) {
    return false;
}
~~~

O método também consulta estados no `user_meta`, como `ig_rm_feedback_review_done`, e pode suprimir o aviso depois que o usuário responde (`class-ig-feedback.php:150-192`). Um Subscriber ou visitante não passa pelo filtro padrão; a checagem de capacidade é o limite de acesso decisivo.

## 3. Como o nonce entra no link

Quando o aviso é mostrado, o plugin gera um nonce para a ação `review` e o coloca no link “Ok, you deserve it” junto com a ação e o destino de avaliação (`class-ig-feedback.php:249-251`):

~~~php
$nonce = wp_create_nonce( 'review' );
$review_url = add_query_arg( 'review_url', $review_url, add_query_arg( 'ig_feedback_nonce', $nonce, add_query_arg( 'ig_feedback_action', $review_done_option, $current_page_url ) ) );
~~~

O destino gerado normalmente é a página de avaliações do plugin no WordPress.org (`class-ig-feedback.php:233`). O nonce aparece no HTML entregue ao administrador elegível. Não encontrei, neste fluxo, uma forma de uma conta de baixo privilégio obter o nonce da sessão de outra pessoa.

## 4. Da query string ao sink

Na requisição feita ao clicar no link, `show_review_notice()` verifica `ig_feedback_nonce` com `wp_verify_nonce()` e só continua se a ação for válida (`class-ig-feedback.php:200-213`):

~~~php
$nonce_verified = wp_verify_nonce( $nonce, 'review' );
if ( $nonce_verified ) {
    $action = ! empty( $_GET['ig_feedback_action'] ) ? esc_attr( wp_unslash( $_GET['ig_feedback_action'] ) ) : '';
~~~

Para chegar ao redirecionamento, a ação deve corresponder a `ig_rm_feedback_review_done`. Antes da saída, o código grava essa ação no `user_meta`; por isso, a tentativa também marca o aviso como concluído para aquele usuário.

A fonte controlável é `$_GET['review_url']`. O valor não recebe validação de destino nem escape de atributo antes da impressão (`class-ig-feedback.php:215-220`):

~~~php
$url = ! empty( $_GET['review_url'] ) ? $_GET['review_url'] : '';
if ( ! empty( $url ) ) {
    ?>
    <meta http-equiv="refresh" content="0; url=<?php echo $url; ?>"/>
    <?php
}
~~~

O sink é um atributo HTML delimitado por aspas duplas. Uma aspa dupla em `review_url` pode fechar o atributo `content` e permitir que a sequência seguinte seja interpretada como nova marcação. Essa conclusão é estática; a execução em navegador não foi observada nesta análise.

## 5. Limites da evidência

A análise estática confirma a interpolação sem escape, mas não registra uma execução de JavaScript no navegador. Um teste local exigiria uma sessão administrativa elegível, o aviso visível e o nonce daquele usuário. Ao seguir a ação de avaliação, o plugin marca o aviso como concluído no `user_meta`, o que afeta novas tentativas na mesma conta.

## 6. Impacto e correção

A falha concreta é imprimir um parâmetro da requisição sem escape no contexto de um atributo HTML. O código revisado não mostra uma cadeia em que um visitante ou Subscriber obtenha o nonce de um administrador e o faça abrir uma URL alterada. Portanto, não há impacto real **demonstrado para um atacante externo** nesta análise. Uma divulgação como XSS explorável por baixo privilégio, com CVE ou severidade atribuída, não seria sustentada por essas evidências.

A correção mais simples é construir o destino de avaliação no servidor, a partir do identificador do plugin, sem aceitar `review_url` da query string. Se o parâmetro continuar necessário, valide o protocolo e o host permitido e escape o valor completo do atributo imediatamente antes da saída. Um teste de regressão deve cobrir aspas e tags em `review_url`, além de confirmar que requisições sem nonce válido ou sem `manage_options` não alcançam a saída.

## Conclusão

O caminho `Rainmaker::__construct() → IG_Feedback_V_1_2_5::__construct() → admin_notices → show_review_notice() → filtro de elegibilidade → nonce/ação → $_GET['review_url'] → atributo content` confirma uma saída sem escape no pacote 1.3.21. O limite de privilégio e o nonce impedem, com as evidências disponíveis, afirmar uma exploração por usuário externo ou de baixo privilégio.