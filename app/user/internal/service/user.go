package service

import (
	"context"
	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/protobuf/types/known/emptypb"
	v1 "kratos-x509/api/user/v1"
)

type UserService struct {
	v1.UnimplementedUserServiceServer

	log *log.Helper
}

func NewUserService(logger log.Logger) *UserService {
	l := log.NewHelper(log.With(logger, "module", "service/user"))
	return &UserService{
		log: l,
	}
}

func (s *UserService) ListUser(_ context.Context, _ *emptypb.Empty) (*v1.ListUserReply, error) {
	return &v1.ListUserReply{}, nil
}

func (s *UserService) GetUser(_ context.Context, req *v1.GetUserRequest) (*v1.User, error) {
	var id uint64 = 10
	var email = "hello@kratos.com"
	var roles []string
	switch req.UserName {
	case "admin":
		roles = append(roles, "ROLE_ADMIN")
	case "moderator":
		roles = append(roles, "ROLE_MODERATOR")
	}
	return &v1.User{
		Id:       &id,
		UserName: &req.UserName,
		Email:    &email,
		Roles:    roles,
	}, nil
}
