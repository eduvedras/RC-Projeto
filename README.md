# Redes de Computadores, Grupo:01 LEIC-A 2021/2022

    73783 - Ana Sofia Das Neves Moreira
    95569 - Eduardo Moreira Miranda
    95578 - Francisco Manuel Leal Mithá Ribeiro

Programming using the Sockets interface
“RC Centralized Messaging”

Lista de Comandos:

    reg UID PASS - registar novo utilizador UID
    unregister UID pass // unr UID pass – eliminar utilizador UID
    login UID pass – iniciar uma sessão com o utilizador UID
    logout – terminar a sessão atual
    showuid // su – mostrar UID do utilizador atual
    exit – sair da aplicação
    groups // gl – listar todos os grupos do servidor
    subscribe GID GName // s GID GName – utilizador atual subscreve grupo GID de nome GName
    unsubscribe GID // u GID – utilizador atual remove a subscrição do grupo GID
    my_groups // mgl – listar todos os grupos subscritos pelo utilizador atual
    select GID // sag GID – selecionar grupo GID
    showgid // sg – mostrar grupo selecionado
    ulist // ul – listar todos os utilizadores subscritos ao grupo selecionado
    post “text” [Fname] – enviar mensagem "text" (e ficheiro Fname) para o grupo selecionado
    retrieve MID // r MID – receber até 20 mensagens a começar da mensagem MID

Restrições:

    UID - 5 dígitos
    PASS - 8 caracteres
    GID - 2 dígitos
    GName - até 24 caracteres
    text - até 240 caracteres
    Fname - até 24 caracteres
    MID - 4 dígitos

Diretorias Criadas:

    'downloads' - onde todos os ficheiros descarregados pelo cliente estão guardados
    'GROUPS' - onde a informação de grupos de um servidor DS é guardada
    'USERS' - ondea informação de utilizadores de um servidor DS é guardada