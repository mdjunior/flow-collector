FLOW COLLECTOR
==============

Coletor e analisador de datagramas Netflow com integracao com a NMAP::API e a REPUTATION::API.


Instalação
----------

Para usar o FLOW COLLECTOR 

* [Readonly](https://metacpan.org/pod/Readonly) -- Usado para gerar as constantes
* [Net::Syslog](https://metacpan.org/pod/Net::Syslog) -- Usado para o envio de eventos via syslog
* [Sys::Syslog](https://metacpan.org/pod/Sys::Syslog) -- Usado para o envio de eventos localmente
* [Net::Subnet](https://metacpan.org/pod/Net::Subnet) -- Usado para fazer o match de endereços IP
* [Mojo::UserAgent](https://metacpan.org/pod/Mojo::UserAgent) -- Usado para fazer o envio de dados para a REPUTATION::API e a obteção de dados da NMAP::API

Se você estiver instalando somente para testar, você pode executar:

	cpanm Readonly Net::Syslog Sys::Syslog Net:Subnet Mojo::UserAgent

Se você estiver instalando a aplicação para um ambiente de produção, é recomendável que você faça uso da [local::lib](https://metacpan.org/pod/local::lib) para não modificar o Perl instalado em seu sistema. Outra alternativa é usar o [perlbrew](http://perlbrew.pl/).

Para instalar o locallib é recomendado que você crie um usuário limitado para sua aplicação, no caso, você pode criar um usuário chamado `flow_collector` e instalar o [local::lib](https://metacpan.org/pod/local::lib) no home desse usuário.

	cpanm local::lib

Após instalar é necessário acrescentar no arquivo `.bashrc` ou `.profile` as variáveis de ambiente para a sua aplicação. Para obtê-las, execute `perl -Mlocal::lib`.


Configuração
------------

A configuração da API é feita por variáveis de ambiente. Um exemplo de configuração pode ser visto a seguir:

	export FLOW_COLLECTOR_LOG="LOCAL"
	export FLOW_COLLECTOR_PORT="9993"
	export FLOW_COLLECTOR_IPTYPE="IPV4"

	export FLOW_CONNECTOR_NMAP_API_USER="user"
	export FLOW_CONNECTOR_NMAP_API_PASS="pass"
	export FLOW_CONNECTOR_NMAP_API_HOST="192.168.150.102"
	export FLOW_CONNECTOR_NMAP_API_PROTOCOL="https"

	export FLOW_CONNECTOR_REPUTATION_API_USER="user"
	export FLOW_CONNECTOR_REPUTATION_API_PASS="pass"
	export FLOW_CONNECTOR_REPUTATION_API_HOST="localhost"
	export FLOW_CONNECTOR_REPUTATION_API_PROTOCOL="http"
	export FLOW_CONNECTOR_REPUTATION_API_PORT="3000"

	export FLOW_CONNECTOR_NETWORK="10.0.0.0/8"
	export FLOW_CONNECTOR_SRC_TRUSTED="10.10.10.1"
	export FLOW_CONNECTOR_HONEYPOTS="10.10.0.0/24 10.10.3.0/24"
	export FLOW_CONNECTOR_DST_TRUSTED="8.8.8.8 10.10.0.0/16"
	export FLOW_CONNECTOR_DARKNET="10.11.0.0/16"

Nesse exemplo, colocamos os eventos para serem gerados localmente, logo deverá ser criada no diretório da aplicação uma pasta chamada `log`.

No exemplo a seguir, configuramos para o envio de eventos para um coletor remoto:

	export FLOW_COLLECTOR_LOG="NET"
	export FLOW_COLLECTOR_SYSLOG_PORT="514"
	export FLOW_COLLECTOR_SYSLOG_HOST="192.168.0.32"
	export FLOW_COLLECTOR_PORT="9993"
	export FLOW_COLLECTOR_IPTYPE="IPV4"

	export FLOW_CONNECTOR_NMAP_API_USER="user"
	export FLOW_CONNECTOR_NMAP_API_PASS="pass"
	export FLOW_CONNECTOR_NMAP_API_HOST="192.168.150.102"
	export FLOW_CONNECTOR_NMAP_API_PROTOCOL="https"

	export FLOW_CONNECTOR_REPUTATION_API_USER="user"
	export FLOW_CONNECTOR_REPUTATION_API_PASS="pass"
	export FLOW_CONNECTOR_REPUTATION_API_HOST="localhost"
	export FLOW_CONNECTOR_REPUTATION_API_PROTOCOL="http"
	export FLOW_CONNECTOR_REPUTATION_API_PORT="3000"

	export FLOW_CONNECTOR_NETWORK="10.0.0.0/8"
	export FLOW_CONNECTOR_SRC_TRUSTED="10.10.10.1"
	export FLOW_CONNECTOR_HONEYPOTS="10.10.0.0/24 10.10.3.0/24"
	export FLOW_CONNECTOR_DST_TRUSTED="8.8.8.8 10.10.0.0/16"
	export FLOW_CONNECTOR_DARKNET="10.11.0.0/16"

Nesse exemplo, os eventos serão enviados via Syslog para o host 192.168.0.32, na porta 514.


Uso
---

O uso é bem simples basta executar a aplicação e configurar os equipamentos de rede para enviar os flows para a porta definida em FLOW_COLLECTOR_PORT.


Limitações
--------------------

* A aplicação somente é capaz de receber flows na versão 1 e na versão 5. Em versões futuras será implementada a capacidade de receber novas versões.
* A aplicação também só faz a checagem dos flows do protocolo TCP com flags.

Licenciamento
-------------

Esse software é livre e deve ser distribuido sobre os termos a Apache License v2.


Autor
-----

Copyrigth [Manoel Domingues Junior](http://github.com/mdjunior) <manoel at ufrj dot br>

