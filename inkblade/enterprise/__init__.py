# -*- coding: utf-8 -*-
"""企业集成适配层（本地可测，不冒充生产 IdP/SIEM）。

边界：OIDC/LDAP 默认使用 **mock IdP/目录**；Splunk/Elastic/Webhook/Jira/ServiceNow
适配器只保证「请求契约」可被本地 HTTP 收包器验证，真实客户环境仍需联调、
证书/代理/网络白名单与字段映射确认。

2026-10-26 新增本地可验证层：registry 认证/代理、保留删除执行、变更冻结/
云厂商例外/规则回归、SIEM 去重与死信、出网策略、合规证据包、审计事件流规模、
GPU Operator/device plugin/DRA 契约。全部只在本机 mock/临时目录验证。
"""

from .approval import ApprovalChain, ApprovalError
from .auth import AuthError, LDAPAdapter, MockLDAPDirectory, OIDCAdapter, session_from_identity
from .delivery import DeliveryPolicyError, DeliveryQueue, Deduplicator, EgressPolicy
from .evidence_pack import EvidencePackError, build_pack, verify_pack
from .governance import (ChangeCalendar, ExceptionPolicy, GovernanceError,
                         assert_no_regression, compare_rule_packs)
from .gpu_contract import compatibility_matrix, validate_device_plugin, validate_dra
from .registry import ProxyConfig, RegistryClient, RegistryError, parse_reference
from .report_signing import (
    SignoffError,
    create_signoff,
    retention_plan,
    sign_report,
    verify_report,
)
from .retention import RetentionError, apply_retention
from .scale import daily_million_projection, run_scale
from .siem import (
    DeliveryError,
    ElasticBulk,
    JiraSink,
    ServiceNowSink,
    SplunkHEC,
    WebhookSink,
)

__all__ = [
    "ApprovalChain", "ApprovalError", "AuthError", "LDAPAdapter", "MockLDAPDirectory",
    "OIDCAdapter", "SignoffError", "create_signoff", "retention_plan", "sign_report",
    "verify_report", "DeliveryError", "ElasticBulk", "JiraSink", "ServiceNowSink",
    "SplunkHEC", "WebhookSink", "session_from_identity",
    "RegistryError", "RegistryClient", "ProxyConfig", "parse_reference",
    "RetentionError", "apply_retention",
    "GovernanceError", "ChangeCalendar", "ExceptionPolicy", "compare_rule_packs",
    "assert_no_regression",
    "DeliveryPolicyError", "Deduplicator", "DeliveryQueue", "EgressPolicy",
    "EvidencePackError", "build_pack", "verify_pack",
    "run_scale", "daily_million_projection",
    "validate_device_plugin", "validate_dra", "compatibility_matrix",
]
