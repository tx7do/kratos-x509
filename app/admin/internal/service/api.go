package service

import (
	"context"
	"fmt"
	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/protobuf/types/known/emptypb"
	v1 "kratos-x509/api/admin/v1"
	userV1 "kratos-x509/api/user/v1"
)

type AdminService struct {
	v1.UnimplementedAdminServiceServer

	log  *log.Helper
	user userV1.UserServiceClient
}

func NewAdminService(user userV1.UserServiceClient, logger log.Logger) *AdminService {
	l := log.NewHelper(log.With(logger, "module", "service/admin"))
	return &AdminService{
		log:  l,
		user: user,
	}
}

func (s *AdminService) Login(ctx context.Context, req *v1.LoginReq) (*v1.User, error) {
	fmt.Println("Login", req.UserName, req.Password)

	ret, err := s.user.GetUser(ctx, &userV1.GetUserRequest{
		UserName: req.UserName,
	})
	if err != nil {
		return nil, err
	}

	return &v1.User{
		Id:       ret.Id,
		UserName: ret.UserName,
		Email:    ret.Email,
		Roles:    ret.Roles,
	}, nil
}

func (s *AdminService) Logout(_ context.Context, _ *v1.LogoutReq) (*v1.LogoutReply, error) {
	return nil, nil
}

func (s *AdminService) Register(_ context.Context, _ *v1.RegisterReq) (*v1.RegisterReply, error) {
	return &v1.RegisterReply{
		Message: "register success",
		Success: true,
	}, nil
}

func (s *AdminService) GetUser(context.Context, *emptypb.Empty) (*v1.User, error) {
	var id uint64 = 10
	var email = "hello@kratos.com"
	var roles []string
	return &v1.User{
		Id:    &id,
		Email: &email,
		Roles: roles,
	}, nil
}
