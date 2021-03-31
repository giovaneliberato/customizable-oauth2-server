package token

import (
	"encoding/json"
	"fmt"
	"oauth2-server/infra"
)

func monitorExchangeError(req AuthorizationCodeRequest, err error) {
	reqJson, _ := json.Marshal(req)
	errJson, _ := json.Marshal(err)
	msg := fmt.Sprintf("ExchangeSuccess: req=%s error=%s", string(reqJson), string(errJson))
	infra.LOGGER.Info().Msg(msg)
}

func monitorExchangeSuccess(req AuthorizationCodeRequest) {
	reqJson, _ := json.Marshal(req)
	msg := fmt.Sprintf("ExchangeSuccess: req=%s", string(reqJson))
	infra.LOGGER.Info().Msg(msg)
}
