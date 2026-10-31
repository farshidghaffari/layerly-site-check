"""Opt-in 100-page discovery, boundaries and compatibility without external traffic."""
import copy
import contextlib
import io
import unittest
from unittest.mock import patch

from sitecheck.check import CheckRun
from sitecheck.cli import main
from sitecheck.config import Limits
from sitecheck.fixtures import H,IP_SITE,TEXT,make,ok,page,redirect,run_sample
from sitecheck.transport import FixtureResponse
from sitecheck.validate import validate_report

def run_extended(routes,limits=None):
    limits=limits or Limits(max_pages=100,max_requests=400,job_timeout_s=600)
    resolver,transport,clock=make({H:[IP_SITE]},routes,limits)
    report=CheckRun('https://'+H+'/',resolver=resolver,transport=transport,clock=clock,limits=limits,recursive=True,explain=False).run()
    return report,transport

def chain(count):
    routes={(H,'/robots.txt'):FixtureResponse(404,dict(TEXT),b'')}
    for i in range(count):
        path='/' if i==0 else '/p'+str(i)+'/'
        target='/p'+str(i+1)+'/'
        routes[(H,path)]=ok(page(links=((target,'Next'),) if i+1<count else ()))
    return routes

class ExtendedCrawl(unittest.TestCase):
    def test_reaches_deep_pages_and_exact_100_boundary(self):
        r,t=run_extended(chain(100))
        self.assertEqual(r['coverage']['pages_fetched'],100)
        self.assertEqual(r['coverage']['requests_used'],101)
        self.assertEqual(r['status'],'complete')
        self.assertEqual(r['schema_version'],'layerly.check.v0.5-draft')
        self.assertIn('up to 100 pages',r['disclaimer'])
        self.assertEqual(validate_report(r),[])

    def test_page_cap_is_reported_and_never_fetches_page_101(self):
        r,t=run_extended(chain(105))
        self.assertEqual(r['coverage']['pages_selected'],100)
        self.assertEqual(r['coverage']['stopped_reason'],'page_limit_reached')
        self.assertEqual(r['status'],'partial')
        self.assertNotIn('/p100/',[x['path'] for x in t.log if x['method']=='GET'])
        self.assertEqual(validate_report(r),[])

    def test_recursive_discovery_deduplicates_cycles_and_tracking_urls(self):
        routes=chain(10)
        routes[(H,'/p9/')]=ok(page(links=(('/','Home'),('/p1/?utm_source=test','Track'),('/p1/#fragment','Fragment'))))
        r,t=run_extended(routes)
        self.assertEqual(r['coverage']['pages_selected'],10)
        gets=[x['path'] for x in t.log if x['method']=='GET' and x['path']!='/robots.txt']
        self.assertEqual(len(gets),len(set(gets)))

    def test_breadth_first_after_homepage(self):
        routes=chain(1)
        routes[(H,'/')]=ok(page(links=(('/a/','A'),('/b/','B'))))
        routes[(H,'/a/')]=ok(page(links=(('/deep/','Deep'),)))
        routes[(H,'/b/')]=ok(page())
        routes[(H,'/deep/')]=ok(page())
        r,t=run_extended(routes)
        self.assertEqual([x['url'] for x in r['pages']],['https://'+H+x for x in ['/','/a/','/b/','/deep/']])

    def test_robots_still_precedes_and_blocks_deep_page(self):
        routes=chain(3);routes[(H,'/robots.txt')]=ok(b'User-agent: *\nDisallow: /p2/\n',TEXT)
        r,t=run_extended(routes)
        self.assertNotIn('/p2/',[x['path'] for x in t.log])
        self.assertEqual(r['coverage']['pages_skipped'],1)
        self.assertEqual(validate_report(r),[])

    def test_request_budget_still_stops_recursive_discovery(self):
        r,t=run_extended(chain(100),Limits(max_pages=100,max_requests=8,job_timeout_s=600))
        self.assertEqual(len(t.log),8)
        self.assertEqual(r['coverage']['requests_used'],8)
        self.assertEqual(r['coverage']['stopped_reason'],'request_budget_exhausted')
        self.assertEqual(r['status'],'partial')
        self.assertEqual(validate_report(r),[])

    def test_job_timeout_still_stops_recursive_discovery(self):
        r,t=run_extended(chain(100),Limits(max_pages=100,max_requests=400,job_timeout_s=2))
        self.assertEqual(r['coverage']['stopped_reason'],'job_timeout')
        self.assertEqual(r['status'],'partial')
        self.assertLess(r['coverage']['pages_selected'],100)
        self.assertEqual(validate_report(r),[])

    def test_external_and_private_literal_links_are_not_requested(self):
        routes=chain(1);routes[(H,'/')]=ok(page(links=(('https://other.example/','Other'),('http://127.0.0.1/','Private'))))
        r,t=run_extended(routes)
        self.assertTrue(all(x['host']==H for x in t.log))
        self.assertEqual(r['coverage']['links_not_checked'],2)
        self.assertEqual(validate_report(r),[])

    def test_validator_rejects_over_selected_limit_and_mismatched_budget(self):
        r,_=run_extended(chain(6))
        bad=copy.deepcopy(r);bad['limits']['max_pages']=5
        self.assertIn('selected pages exceed configured page limit',validate_report(bad))
        bad=copy.deepcopy(r);bad['coverage']['requests_limit']=399
        self.assertIn('coverage and configured budgets differ',validate_report(bad))

    def test_legacy_fixture_remains_v04_and_valid(self):
        r,_=run_sample()
        self.assertEqual(r['schema_version'],'c2.check.v0.4-draft')
        self.assertEqual(r['limits']['max_pages'],5)
        self.assertEqual(validate_report(r),[])

    def test_cli_refuses_invalid_caps_and_no_live_flag(self):
        for value in ['0','101','-1']:
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                main(['check','https://'+H,'--max-pages',value])
        with contextlib.redirect_stderr(io.StringIO()),patch('sitecheck.resolver.SystemResolver') as resolver:
            self.assertEqual(main(['check','https://'+H,'--max-pages','100']),2)
            resolver.assert_not_called()

    def test_cli_passes_opt_in_profile_without_real_network(self):
        r,_=run_extended(chain(6),Limits(max_pages=6,max_requests=24))
        with contextlib.redirect_stdout(io.StringIO()),patch('sitecheck.check.run_check',return_value=r) as check:
            self.assertEqual(main(['check','https://'+H,'--live','--max-pages','6']),0)
        self.assertTrue(check.call_args.kwargs['recursive'])
        self.assertEqual(check.call_args.kwargs['limits'].max_requests,24)

if __name__=='__main__':unittest.main()
