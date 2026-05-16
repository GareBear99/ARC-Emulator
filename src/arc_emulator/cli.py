from __future__ import annotations
import argparse, json
from pathlib import Path
from arc_emulator import __version__
from arc_emulator.arc.binary_store import BinaryStore
from arc_emulator.arc.receipts import rom_pack_receipt, session_receipt
from arc_emulator.core.media_identifier import identify_media
from arc_emulator.core.session import create_session
from arc_emulator.core.save_state import create_save_state, verify_save_state
from arc_emulator.core.replay import replay_plan
from arc_emulator.systems.n64.header import parse_n64_header

def print_json(obj): print(json.dumps(obj, indent=2, sort_keys=True))
def cmd_doctor(args): print_json({'ok':True,'name':'arc-emulator','version':__version__,'legal_note':'No ROMs, BIOS files, firmware, keys, or copyrighted assets are provided.','systems_order':['n64','gamecube','ps2','psp']})
def cmd_identify(args):
    info=identify_media(args.path)
    if 'n64' in info.get('system_candidates',[]) and Path(args.path).exists(): info['n64_header']=parse_n64_header(args.path)
    print_json(info)
def cmd_pack(args):
    store=BinaryStore(args.store); info=identify_media(args.path); system=args.system or (info['system_candidates'][0] if info['system_candidates'] else 'unknown')
    manifest=store.pack_file(args.path, kind='rom_or_disc', metadata={'system':system,'identity':info})
    receipt=store.write_receipt(rom_pack_receipt(system, manifest)); print_json({'manifest':manifest,'receipt':receipt})
def cmd_create_session(args):
    store=BinaryStore(args.store); session=create_session(store.root,args.system,args.title or '')
    receipt=store.write_receipt(session_receipt(session['session_id'],args.system,args.title or '')); print_json({'session':session,'receipt':receipt})
def cmd_save_state(args):
    store=BinaryStore(args.store); print_json(create_save_state(store,args.session,args.system,args.state_file))
def cmd_verify_state(args): print_json(verify_save_state(args.manifest))
def cmd_replay_plan(args): print_json(replay_plan(args.session,args.system))
def cmd_smoke(args): print_json({'ok':True,'version':__version__,'systems_order':['n64','gamecube','ps2','psp'],'message':'arc-emulator smoke passed'})
def build_parser():
    p=argparse.ArgumentParser(prog='arc-emulator'); sub=p.add_subparsers(dest='cmd', required=True)
    d=sub.add_parser('doctor'); d.set_defaults(func=cmd_doctor)
    i=sub.add_parser('identify'); i.add_argument('path'); i.set_defaults(func=cmd_identify)
    pack=sub.add_parser('pack'); pack.add_argument('path'); pack.add_argument('--store',default='.arc_emulator_store'); pack.add_argument('--system',choices=['n64','gamecube','ps2','psp','unknown'],default=None); pack.set_defaults(func=cmd_pack)
    cs=sub.add_parser('create-session'); cs.add_argument('--store',default='.arc_emulator_store'); cs.add_argument('--system',required=True,choices=['n64','gamecube','ps2','psp']); cs.add_argument('--title',default=''); cs.set_defaults(func=cmd_create_session)
    ss=sub.add_parser('save-state'); ss.add_argument('--store',default='.arc_emulator_store'); ss.add_argument('--session',required=True); ss.add_argument('--system',required=True,choices=['n64','gamecube','ps2','psp']); ss.add_argument('--state-file',required=True); ss.set_defaults(func=cmd_save_state)
    vs=sub.add_parser('verify-state'); vs.add_argument('manifest'); vs.set_defaults(func=cmd_verify_state)
    rp=sub.add_parser('replay-plan'); rp.add_argument('--session',required=True); rp.add_argument('--system',required=True,choices=['n64','gamecube','ps2','psp']); rp.set_defaults(func=cmd_replay_plan)
    sm=sub.add_parser('smoke'); sm.set_defaults(func=cmd_smoke)
    return p
def main(argv=None):
    parser=build_parser(); args=parser.parse_args(argv); args.func(args)
if __name__ == '__main__': main()
