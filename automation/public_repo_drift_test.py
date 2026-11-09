import subprocess
import unittest
from unittest.mock import patch
import public_repo_drift as audit

class ApiEvidenceTests(unittest.TestCase):
    def test_timeout_is_explicitly_unavailable(self):
        with patch.object(audit.subprocess,'run',side_effect=subprocess.TimeoutExpired('gh',60)):
            self.assertEqual(audit.api('repos/example/repo'),{'unavailable':'timeout'})

    def test_http_error_does_not_become_zero_coverage(self):
        response=subprocess.CompletedProcess(['gh'],1,stdout='',stderr='API read failed (HTTP 403)')
        with patch.object(audit.subprocess,'run',return_value=response):
            self.assertEqual(audit.api('repos/example/repo'),{'unavailable':'403'})

    def test_thread_resolution_is_a_pull_request_parameter(self):
        rules=[{'type':'deletion'},{'type':'non_fast_forward'},
               {'type':'pull_request','parameters':{'required_review_thread_resolution':True}}]
        def response(path,paginate=False):
            if '/rules/branches/' in path:return rules
            if '/rulesets?' in path:return []
            return {'tree':[]}
        with patch.object(audit,'api',side_effect=response):
            result=audit.audit({'full_name':'example/repo','default_branch':'main'})
        self.assertNotIn('unresolved-review-threads-permitted',result['drift'])
        self.assertIn('missing-version-tag-protection',result['drift'])

if __name__=='__main__':unittest.main()
