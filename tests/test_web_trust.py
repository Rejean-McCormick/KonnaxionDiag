from __future__ import annotations
import tempfile
from pathlib import Path
from profiles.security.levels.s04_app_production import _check_web_trust_boundaries

class Report:
    def __init__(self):self.findings=[]
    def add(self,finding_id,verdict,category,message,**kwargs):self.findings.append({'id':finding_id,'verdict':verdict,'category':category,'message':message,**kwargs})
    def verdict(self,finding_id):return next(x['verdict'] for x in self.findings if x['id']==finding_id)

def write(root,rel,text):
    p=root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text,encoding='utf-8')

def test_hardened_fixture_breaks_clickfix_and_upload_chains():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)
        write(root,'backend/config/settings/production.py','ACCOUNT_ALLOW_REGISTRATION = env.bool("DJANGO_ACCOUNT_ALLOW_REGISTRATION", default=False)\n')
        write(root,'backend/config/settings/base.py','DEFAULT_THROTTLE_CLASSES = ()\nDEFAULT_THROTTLE_RATES = {}\n')
        write(root,'backend/konnaxion/users/adapters.py','getattr(settings, "ACCOUNT_ALLOW_REGISTRATION", False)\n')
        write(root,'backend/konnaxion/security_controls.py','def validate_safe_upload(x): pass\n')
        write(root,'backend/konnaxion/konnected/api_views.py','class KnowledgeResourceViewSet:\n permission_classes = [StaffWritePublicReadPermission]\n')
        write(root,'backend/konnaxion/konnected/serializers.py','from x import validate_safe_external_url\ndef validate_url(self, value): return validate_safe_external_url(value)\n')
        write(root,'backend/konnaxion/keenkonnect/api_views.py','OwnerOrStaffWritePermission\nProjectManagerWritePermission\nSelfOrStaffWritePermission\n')
        write(root,'backend/konnaxion/keenkonnect/serializers.py','validate_safe_upload\n')
        write(root,'backend/konnaxion/kreative/api_views.py','OwnerOrStaffWritePermission\nStaffWritePublicReadPermission\n')
        write(root,'backend/konnaxion/kreative/serializers.py','validate_safe_upload\n')
        write(root,'backend/konnaxion/trust/serializers.py','validate_safe_upload\n')
        write(root,'backend/config/websocket.py','Origin\ndef _origin_is_allowed(): pass\n4403\n')
        write(root,'backend/compose/production/nginx/default.conf',"add_header X-Content-Type-Options nosniff;\nadd_header Content-Security-Policy \"sandbox; script-src 'none'\";\nlocation ~* html|svg|xml|js { return 403; }\n")
        write(root,'frontend/middleware.ts',"Content-Security-Policy\nnonce-${nonce}\nstrict-dynamic\nscript-src-attr 'none'\nobject-src 'none'\nframe-ancestors 'none'\n")
        write(root,'frontend/lib/security/navigation.ts',"export function openExternalUrlSafely() { window.open('x', '_blank', 'noopener,noreferrer'); }\n")
        write(root,'frontend/app/%5Fapi/search/route.ts','const base = process.env.INTERNAL_API_BASE;\n')
        report=Report();_check_web_trust_boundaries({},report,root,{})
        assert report.verdict('app.web_trust.clickfix_delivery_chain')=='PASS'
        assert report.verdict('app.web_trust.stored_active_content_chain')=='PASS'
        assert report.verdict('app.web_trust.browser_sinks')=='PASS'

def test_vulnerable_fixture_correlates_clickfix_chain():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)
        write(root,'backend/config/settings/production.py','')
        write(root,'backend/config/settings/base.py','')
        write(root,'backend/konnaxion/users/adapters.py','getattr(settings, "ACCOUNT_ALLOW_REGISTRATION", True)\n')
        write(root,'backend/konnaxion/konnected/api_views.py','class KnowledgeResourceViewSet:\n permission_classes=[permissions.IsAuthenticatedOrReadOnly]\n')
        write(root,'backend/konnaxion/konnected/serializers.py','')
        write(root,'frontend/app/page.tsx','dangerouslySetInnerHTML={{__html: x}}; window.open(url);\n')
        write(root,'frontend/lib/security/navigation.ts','')
        report=Report();_check_web_trust_boundaries({},report,root,{})
        assert report.verdict('app.web_trust.clickfix_delivery_chain')=='FAIL'
