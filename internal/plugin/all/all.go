// Package all habilita os plugins embutidos. Para adicionar um plugin,
// crie o pacote dele e acrescente o import aqui.
package all

import (
	_ "janus/internal/plugin/logs/ucg"
	_ "janus/internal/plugin/wifi/unifi"
)
