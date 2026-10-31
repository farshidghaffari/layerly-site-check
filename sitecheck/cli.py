"""CLI for the standalone, key-free Layerly checker."""
import argparse
import json
import sys
from .config import Limits
from .errors import CheckError
from .validate import validate_report

def main(argv=None):
    parser=argparse.ArgumentParser(prog='layerly-check',description='Evidence-based checks of 5 pages by default, up to 100 with --max-pages.')
    sub=parser.add_subparsers(dest='command',required=True)
    demo=sub.add_parser('demo',help='offline fixture: no network requests')
    demo.add_argument('--scenario',default='sample');demo.add_argument('--list',action='store_true');demo.add_argument('--out')
    validate=sub.add_parser('validate',help='validate a full report JSON');validate.add_argument('file')
    check=sub.add_parser('check',help='check an authorised public website')
    check.add_argument('url');check.add_argument('--live',action='store_true',help='explicitly enable real network requests')
    check.add_argument('--out');check.add_argument('--lang',choices=('en','hy'),default='en')
    check.add_argument('--max-pages',type=int,default=5,help='HTML page selection cap, 1 to 100; values above 5 enable recursive discovery')
    args=parser.parse_args(argv)
    if args.command=='check' and not 1 <= args.max_pages <= 100:
        parser.error('--max-pages must be between 1 and 100')
    if args.command=='validate':
        with open(args.file,encoding='utf-8') as f:errors=validate_report(json.load(f))
        print('OK' if not errors else '\n'.join(errors));return int(bool(errors))
    if args.command=='demo':
        from .fixtures import SCENARIOS,run_scenario
        if args.list:print('\n'.join(sorted(SCENARIOS)));return 0
        if args.scenario not in SCENARIOS:parser.error('unknown demo scenario')
        report=run_scenario(args.scenario)
    else:
        if not args.live:
            print('No requests sent. Add --live only for a public website you are authorised to check.',file=sys.stderr);return 2
        from .check import run_check
        from .clock import RealClock
        from .resolver import SystemResolver
        from .transport import PinnedTransport
        try:
            limits=Limits(max_pages=args.max_pages,max_requests=max(20,4*args.max_pages),job_timeout_s=max(60,6*args.max_pages))
            report=run_check(args.url,resolver=SystemResolver(),transport=PinnedTransport(),clock=RealClock(),limits=limits,recursive=args.max_pages>5,explain=False,lang=args.lang)
        except CheckError as exc:
            print(json.dumps({'error':{'code':exc.code,'message':exc.message}}));return 1
    errors=validate_report(report)
    if errors:print('Report validation failed: '+'; '.join(errors),file=sys.stderr);return 1
    text=json.dumps(report,ensure_ascii=False,indent=2)+'\n'
    if args.out:
        with open(args.out,'w',encoding='utf-8') as f:f.write(text)
    else:print(text,end='')
    return 0
