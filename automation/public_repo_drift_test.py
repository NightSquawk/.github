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

    def test_flow_style_actions_are_found_without_matching_shell_text(self):
        body='''jobs:
  build:
    steps: [{ uses: actions/checkout@v4 }]
  shell:
    steps:
      - run: |
          uses: not/an-action@v1
'''
        self.assertEqual(audit.action_references(body),['actions/checkout@v4'])

    def test_all_tag_protection_covers_version_tags(self):
        def response(path,paginate=False):
            if '/rules/branches/' in path:return []
            if '/rulesets?' in path:return [{'id':1,'target':'tag','enforcement':'active'}]
            if '/rulesets/1' in path:return {'conditions':{'ref_name':{'include':['~ALL'],'exclude':[]}},'rules':[{'type':'update'},{'type':'deletion'}]}
            return {'tree':[]}
        with patch.object(audit,'api',side_effect=response):
            result=audit.audit({'full_name':'example/repo','default_branch':'main'})
        self.assertNotIn('missing-version-tag-protection',result['drift'])

    def test_non_version_exclusions_do_not_remove_version_protection(self):
        self.assertFalse(audit.may_exclude_version_tags('refs/tags/test-*'))
        self.assertTrue(audit.may_exclude_version_tags('refs/tags/v1.*'))

    def test_tag_rules_are_combined_across_matching_rulesets(self):
        def response(path,paginate=False):
            if '/rules/branches/' in path:return []
            if '/rulesets?' in path:return [{'id':n,'target':'tag','enforcement':'active'} for n in [1,2]]
            if '/rulesets/' in path:return {'conditions':{'ref_name':{'include':['~ALL'],'exclude':['refs/tags/test-*']}},'rules':[{'type':'update' if path.endswith('/1') else 'deletion'}]}
            return {'tree':[]}
        with patch.object(audit,'api',side_effect=response):
            result=audit.audit({'full_name':'example/repo','default_branch':'main'})
        self.assertNotIn('missing-version-tag-protection',result['drift'])

if __name__=='__main__':unittest.main()
