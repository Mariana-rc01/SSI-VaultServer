from dataclasses import dataclass
import json
from typing import Union

@dataclass
class ClientHello:
    tls_version: str
    client_random: str
    cipher_suites: list[str]
    public_key: str

@dataclass
class ServerHello:
    public_key: str
    signature: str
    certificate: str
    server_random: str
    selected_cipher: str

@dataclass
class ClientAuthentication:
    signature: str
    certificate: str
    subject: str

@dataclass
class Notification:
    notifications: list

@dataclass
class AddRequest:
    filename: str
    encrypted_file: str
    encrypted_aes_key: str

@dataclass
class AddResponse:
    response: str

@dataclass
class ReadRequest:
    fileid: str

@dataclass
class ReadResponse:
    filedata: str
    encrypted_key: str

@dataclass
class ListRequest:
    list_type: str
    target_id: str

@dataclass
class ListResponse:
    files: list
    shared: list
    group_files: list

@dataclass
class ShareRequest:
    fileid: str
    target_id: str
    permissions: list
    encrypted_keys: dict
    is_group: bool

@dataclass
class ShareResponse:
    response: str

@dataclass
class PublicKeyRequest:
    user_id: str

@dataclass
class PublicKeyResponse:
    public_key: str

@dataclass
class DeleteRequest:
    file_id: str

@dataclass
class DeleteResponse:
    response: str

@dataclass
class ReplaceRequirementsRequest:
    file_id: str

@dataclass
class ReplaceRequirementsResponse:
    encrypted_key: str

@dataclass
class ReplaceRequest:
    file_id: str
    encrypted_file: str

@dataclass
class ReplaceResponse:
    response: str

@dataclass
class DetailsRequest:
    file_id: str

@dataclass
class DetailsResponse:
    file_id: str
    file_name: str
    file_size: int
    owner: str
    permissions: list
    created_at: str

@dataclass
class RevokeRequest:
    file_id: str
    target_id: str

@dataclass
class RevokeResponse:
    response: str

@dataclass
class GroupMembersRequest:
    group_id: str

@dataclass
class GroupMembersResponse:
    members: list

@dataclass
class GroupCreateRequest:
    group_name: str

@dataclass
class GroupCreateResponse:
    response: str

@dataclass
class GroupDeleteRequest:
    group_id: str

@dataclass
class GroupDeleteResponse:
    response: str

@dataclass
class GroupAddUserRequirementsRequest:
    group_id: str
    user_id: str

@dataclass
class GroupAddUserRequirementsResponse:
    encrypted_keys: dict
    public_key: str

@dataclass
class GroupAddUserRequest:
    group_id: str
    user_id: str
    permission: str
    encrypted_keys: dict

@dataclass
class GroupAddUserResponse:
    response: str

@dataclass
class GroupListRequest:
    pass

@dataclass
class GroupListResponse:
    groups: list

@dataclass
class GroupAddRequest:
    group_id: str
    filename: str
    encrypted_file: str
    encrypted_aes_key: list

@dataclass
class GroupAddResponse:
    response: str

@dataclass
class GroupPublicKeysRequest:
    group_id: str

@dataclass
class GroupPublicKeysResponse:
    public_keys: list

@dataclass
class VaultError:
    error: str

def deserialize_request(data: bytes) -> Union[AddRequest, ReadRequest,
                                              ListRequest, ListResponse, ShareRequest, ShareResponse,
                                              PublicKeyRequest, PublicKeyResponse,
                                              GroupMembersRequest, GroupMembersResponse,
                                              GroupAddUserRequest, GroupAddUserResponse,
                                              GroupAddUserRequirementsRequest, GroupAddUserRequirementsResponse,
                                              GroupListRequest, GroupListResponse,
                                              ReplaceRequirementsRequest, ReplaceRequirementsResponse,
                                              ReplaceRequest, ReplaceResponse, DeleteRequest, DeleteResponse,
                                              DetailsRequest, DetailsResponse, RevokeRequest, RevokeResponse,
                                              GroupAddRequest, GroupAddResponse,
                                              GroupPublicKeysRequest, GroupPublicKeysResponse,
                                              GroupDeleteRequest, GroupDeleteResponse,
                                              Notification, ClientHello, ServerHello,
                                              ClientAuthentication, VaultError]:
    """
        "type": "ClientFirstInteraction",
        "args": {
            "public_key": "adkhasjfbUISAFSF"
        }
    """

    obj = json.loads(data.decode('utf-8')) # bytes -> str -> dict

    op_type = obj.get("type")
    args = obj.get("args")

    if op_type == "ClientHello":
        return ClientHello(**args)
    elif op_type == "ServerHello":
        return ServerHello(**args)
    elif op_type == "ClientAuthentication":
        return ClientAuthentication(**args)
    elif op_type == "Notification":
        return Notification(**args)
    elif op_type == "AddRequest":
        return AddRequest(**args)
    elif op_type == "AddResponse":
        return AddResponse(**args)
    elif op_type == "ReadRequest":
        return ReadRequest(**args)
    elif op_type == "ReadResponse":
        return ReadResponse(**args)
    elif op_type == "ListRequest":
        return ListRequest(**args)
    elif op_type == "ListResponse":
        return ListResponse(**args)
    elif op_type == "ShareRequest":
        return ShareRequest(**args)
    elif op_type == "ShareResponse":
        return ShareResponse(**args)
    elif op_type == "PublicKeyResquest":
        return PublicKeyRequest(**args)
    elif op_type == "PublicKeyResponse":
        return PublicKeyResponse(**args)
    elif op_type == "DeleteRequest":
        return DeleteRequest(**args)
    elif op_type == "DeleteResponse":
        return DeleteResponse(**args)
    elif op_type == "ReplaceRequirementsRequest":
        return ReplaceRequirementsRequest(**args)
    elif op_type == "ReplaceRequirementsResponse":
        return ReplaceRequirementsResponse(**args)
    elif op_type == "ReplaceRequest":
        return ReplaceRequest(**args)
    elif op_type == "ReplaceResponse":
        return ReplaceResponse(**args)
    elif op_type == "DetailsRequest":
        return DetailsRequest(**args)
    elif op_type == "DetailsResponse":
        return DetailsResponse(**args)
    elif op_type == "RevokeRequest":
        return RevokeRequest(**args)
    elif op_type == "RevokeResponse":
        return RevokeResponse(**args)
    elif op_type == "GroupMembersRequest":
        return GroupMembersRequest(**args)
    elif op_type == "GroupMembersResponse":
        return GroupMembersResponse(**args)
    elif op_type == "VaultError":
        return VaultError(**args)
    elif op_type == "GroupCreateRequest":
        return GroupCreateRequest(**args)
    elif op_type == "GroupCreateResponse":
        return GroupCreateResponse(**args)
    elif op_type == "GroupDeleteRequest":
        return GroupDeleteRequest(**args)
    elif op_type == "GroupDeleteResponse":
        return GroupDeleteResponse(**args)
    elif op_type == "GroupAddUserRequest":
        return GroupAddUserRequest(**args)
    elif op_type == "GroupAddUserResponse":
        return GroupAddUserResponse(**args)
    elif op_type == "GroupAddUserRequirementsRequest":
        return GroupAddUserRequirementsRequest(**args)
    elif op_type == "GroupAddUserRequirementsResponse":
        return GroupAddUserRequirementsResponse(**args)
    elif op_type == "GroupListRequest":
        return GroupListRequest()
    elif op_type == "GroupListResponse":
        return GroupListResponse(**args)
    elif op_type == "GroupAddRequest":
        return GroupAddRequest(**args)
    elif op_type == "GroupAddResponse":
        return GroupAddResponse(**args)
    elif op_type == "GroupPublicKeysRequest":
        return GroupPublicKeysRequest(**args)
    elif op_type == "GroupPublicKeysResponse":
        return GroupPublicKeysResponse(**args)
    else:
        raise ValueError(f"Unknow type to deserialize: {op_type}")

def serialize_response(obj: Union[AddRequest, ReadRequest, ListRequest, ListResponse, ShareRequest,
                                  ShareResponse, PublicKeyRequest, PublicKeyResponse,
                                  GroupMembersRequest, GroupMembersResponse,
                                  GroupAddUserRequest, GroupAddUserResponse,
                                  GroupAddUserRequirementsRequest, GroupAddUserRequirementsResponse,
                                  GroupListRequest, GroupListResponse,
                                  ReplaceRequirementsRequest, ReplaceRequirementsResponse,
                                  ReplaceRequest, ReplaceResponse, DeleteRequest, DeleteResponse,
                                  DetailsRequest, DetailsResponse, RevokeRequest, RevokeResponse,
                                  GroupAddRequest, GroupAddResponse,
                                  GroupPublicKeysRequest, GroupPublicKeysResponse,
                                  GroupDeleteRequest, GroupDeleteResponse,
                                  Notification, ClientHello, ServerHello,
                                  ClientAuthentication, VaultError]) -> bytes:
    if isinstance(obj, ClientHello):
        op_type = "ClientHello"
        args = obj.__dict__
    elif isinstance(obj, ServerHello):
        op_type = "ServerHello"
        args = obj.__dict__
    elif isinstance(obj, ClientAuthentication):
        op_type = "ClientAuthentication"
        args = obj.__dict__
    elif isinstance(obj, Notification):
        op_type = "Notification"
        args = obj.__dict__
    elif isinstance(obj, AddRequest):
        op_type = "AddRequest"
        args = obj.__dict__
    elif isinstance(obj, AddResponse):
        op_type = "AddResponse"
        args = obj.__dict__
    elif isinstance(obj, ReadRequest):
        op_type = "ReadRequest"
        args = obj.__dict__
    elif isinstance(obj, ReadResponse):
        op_type = "ReadResponse"
        args = obj.__dict__
    elif isinstance(obj, ListRequest):
        op_type = "ListRequest"
        args = obj.__dict__
    elif isinstance(obj, ListResponse):
        op_type = "ListResponse"
        args = obj.__dict__
    elif isinstance(obj, ShareRequest):
        op_type = "ShareRequest"
        args = obj.__dict__
    elif isinstance(obj, ShareResponse):
        op_type = "ShareResponse"
        args = obj.__dict__
    elif isinstance(obj, PublicKeyRequest):
        op_type = "PublicKeyResquest"
        args = obj.__dict__
    elif isinstance(obj, PublicKeyResponse):
        op_type = "PublicKeyResponse"
        args = obj.__dict__
    elif isinstance(obj, DeleteRequest):
        op_type = "DeleteRequest"
        args = obj.__dict__
    elif isinstance(obj, DeleteResponse):
        op_type = "DeleteResponse"
        args = obj.__dict__
    elif isinstance(obj, ReplaceRequirementsRequest):
        op_type = "ReplaceRequirementsRequest"
        args = obj.__dict__
    elif isinstance(obj, ReplaceRequirementsResponse):
        op_type = "ReplaceRequirementsResponse"
        args = obj.__dict__
    elif isinstance(obj, ReplaceRequest):
        op_type = "ReplaceRequest"
        args = obj.__dict__
    elif isinstance(obj, ReplaceResponse):
        op_type = "ReplaceResponse"
        args = obj.__dict__
    elif isinstance(obj, DetailsRequest):
        op_type = "DetailsRequest"
        args = obj.__dict__
    elif isinstance(obj, DetailsResponse):
        op_type = "DetailsResponse"
        args = obj.__dict__
    elif isinstance(obj, RevokeRequest):
        op_type = "RevokeRequest"
        args = obj.__dict__
    elif isinstance(obj, RevokeResponse):
        op_type = "RevokeResponse"
        args = obj.__dict__
    elif isinstance(obj, GroupMembersRequest):
        op_type = "GroupMembersRequest"
        args = obj.__dict__
    elif isinstance(obj, GroupMembersResponse):
        op_type = "GroupMembersResponse"
        args = obj.__dict__
    elif isinstance(obj, GroupCreateRequest):
        op_type = "GroupCreateRequest"
        args = obj.__dict__
    elif isinstance(obj, GroupCreateResponse):
        op_type = "GroupCreateResponse"
        args = obj.__dict__
    elif isinstance(obj, GroupDeleteRequest):
        op_type = "GroupDeleteRequest"
        args = obj.__dict__
    elif isinstance(obj, GroupDeleteResponse):
        op_type = "GroupDeleteResponse"
        args = obj.__dict__
    elif isinstance(obj, GroupAddUserRequest):
        op_type = "GroupAddUserRequest"
        args = obj.__dict__
    elif isinstance(obj, GroupAddUserResponse):
        op_type = "GroupAddUserResponse"
        args = obj.__dict__
    elif isinstance(obj, GroupAddUserRequirementsRequest):
        op_type = "GroupAddUserRequirementsRequest"
        args = obj.__dict__
    elif isinstance(obj, GroupAddUserRequirementsResponse):
        op_type = "GroupAddUserRequirementsResponse"
        args = obj.__dict__
    elif isinstance(obj, GroupListRequest):
        op_type = "GroupListRequest"
        args = {}
    elif isinstance(obj, GroupListResponse):
        op_type = "GroupListResponse"
        args = obj.__dict__
    elif isinstance(obj, GroupAddRequest):
        op_type = "GroupAddRequest"
        args = obj.__dict__
    elif isinstance(obj, GroupAddResponse):
        op_type = "GroupAddResponse"
        args = obj.__dict__
    elif isinstance(obj, GroupPublicKeysRequest):
        op_type = "GroupPublicKeysRequest"
        args = obj.__dict__
    elif isinstance(obj, GroupPublicKeysResponse):
        op_type = "GroupPublicKeysResponse"
        args = obj.__dict__
    elif isinstance(obj, VaultError):
        op_type = "VaultError"
        args = obj.__dict__
    else:
        raise ValueError(f"Unknow type to serialize: {type(obj)}")

    payload = {
        "type": op_type,
        "args": args
    }

    return json.dumps(payload).encode('utf-8')