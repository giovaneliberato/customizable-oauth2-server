package authorization

import (
	"encoding/json"
	"fmt"
	"oauth2-server/domain"
	"oauth2-server/domain/context"
	"oauth2-server/infra"
)

func monitorAuthorizationSuccess(auth Authorization) {
	authJson, _ := json.Marshal(auth)
	msg := fmt.Sprintf("AuthorizationSuccess: auth=%s", string(authJson))
	infra.LOGGER.Info().Msg(msg)
}

func monitorAuthorizationError(auth Authorization, err *domain.OAuthError) {
	authJson, _ := json.Marshal(auth)
	errJson, _ := json.Marshal(err)
	msg := fmt.Sprintf("AuthorizationError: auth=%s err=%s", string(authJson), string(errJson))
	infra.LOGGER.Error().Msg(msg)
}

func monitorApprovalError(approval AuthorizationApproval, err error) {
	approvalJson, _ := json.Marshal(approval)
	errJson, _ := json.Marshal(err)
	msg := fmt.Sprintf("ApprovalError: approval=%s err=%s", string(approvalJson), string(errJson))
	infra.LOGGER.Error().Msg(msg)
}

func monitorApprovalDenied(approvalCtx context.Context) {
	approvalJson, _ := json.Marshal(approvalCtx)
	msg := fmt.Sprintf("ApprovalError: approval=%s", string(approvalJson))
	infra.LOGGER.Warn().Msg(msg)
}

func monitorApprovalSuccess(approvalCtx context.Context) {
	approvalJson, _ := json.Marshal(approvalCtx)
	msg := fmt.Sprintf("ApprovalSuccess: approval=%s", string(approvalJson))
	infra.LOGGER.Info().Msg(msg)
}
