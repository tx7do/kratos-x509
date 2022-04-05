// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.19.1
// source: admin.proto

package v1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// AdminServiceClient is the client API for AdminService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AdminServiceClient interface {
	// 登陆
	Login(ctx context.Context, in *LoginReq, opts ...grpc.CallOption) (*User, error)
	// 登出
	Logout(ctx context.Context, in *LogoutReq, opts ...grpc.CallOption) (*LogoutReply, error)
	// 注册
	Register(ctx context.Context, in *RegisterReq, opts ...grpc.CallOption) (*RegisterReply, error)
	GetUser(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*User, error)
}

type adminServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAdminServiceClient(cc grpc.ClientConnInterface) AdminServiceClient {
	return &adminServiceClient{cc}
}

func (c *adminServiceClient) Login(ctx context.Context, in *LoginReq, opts ...grpc.CallOption) (*User, error) {
	out := new(User)
	err := c.cc.Invoke(ctx, "/admin.v1.AdminService/Login", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *adminServiceClient) Logout(ctx context.Context, in *LogoutReq, opts ...grpc.CallOption) (*LogoutReply, error) {
	out := new(LogoutReply)
	err := c.cc.Invoke(ctx, "/admin.v1.AdminService/Logout", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *adminServiceClient) Register(ctx context.Context, in *RegisterReq, opts ...grpc.CallOption) (*RegisterReply, error) {
	out := new(RegisterReply)
	err := c.cc.Invoke(ctx, "/admin.v1.AdminService/Register", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *adminServiceClient) GetUser(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*User, error) {
	out := new(User)
	err := c.cc.Invoke(ctx, "/admin.v1.AdminService/GetUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AdminServiceServer is the server API for AdminService service.
// All implementations must embed UnimplementedAdminServiceServer
// for forward compatibility
type AdminServiceServer interface {
	// 登陆
	Login(context.Context, *LoginReq) (*User, error)
	// 登出
	Logout(context.Context, *LogoutReq) (*LogoutReply, error)
	// 注册
	Register(context.Context, *RegisterReq) (*RegisterReply, error)
	GetUser(context.Context, *emptypb.Empty) (*User, error)
	mustEmbedUnimplementedAdminServiceServer()
}

// UnimplementedAdminServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAdminServiceServer struct {
}

func (UnimplementedAdminServiceServer) Login(context.Context, *LoginReq) (*User, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Login not implemented")
}
func (UnimplementedAdminServiceServer) Logout(context.Context, *LogoutReq) (*LogoutReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Logout not implemented")
}
func (UnimplementedAdminServiceServer) Register(context.Context, *RegisterReq) (*RegisterReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Register not implemented")
}
func (UnimplementedAdminServiceServer) GetUser(context.Context, *emptypb.Empty) (*User, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUser not implemented")
}
func (UnimplementedAdminServiceServer) mustEmbedUnimplementedAdminServiceServer() {}

// UnsafeAdminServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AdminServiceServer will
// result in compilation errors.
type UnsafeAdminServiceServer interface {
	mustEmbedUnimplementedAdminServiceServer()
}

func RegisterAdminServiceServer(s grpc.ServiceRegistrar, srv AdminServiceServer) {
	s.RegisterService(&AdminService_ServiceDesc, srv)
}

func _AdminService_Login_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AdminServiceServer).Login(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/admin.v1.AdminService/Login",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AdminServiceServer).Login(ctx, req.(*LoginReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _AdminService_Logout_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LogoutReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AdminServiceServer).Logout(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/admin.v1.AdminService/Logout",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AdminServiceServer).Logout(ctx, req.(*LogoutReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _AdminService_Register_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AdminServiceServer).Register(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/admin.v1.AdminService/Register",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AdminServiceServer).Register(ctx, req.(*RegisterReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _AdminService_GetUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AdminServiceServer).GetUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/admin.v1.AdminService/GetUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AdminServiceServer).GetUser(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

// AdminService_ServiceDesc is the grpc.ServiceDesc for AdminService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AdminService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "admin.v1.AdminService",
	HandlerType: (*AdminServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Login",
			Handler:    _AdminService_Login_Handler,
		},
		{
			MethodName: "Logout",
			Handler:    _AdminService_Logout_Handler,
		},
		{
			MethodName: "Register",
			Handler:    _AdminService_Register_Handler,
		},
		{
			MethodName: "GetUser",
			Handler:    _AdminService_GetUser_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "admin.proto",
}
