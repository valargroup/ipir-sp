"""Retain attempts; select by observed online contention, never timing outcome."""
import json,os,pathlib,subprocess,threading,time
root=pathlib.Path(__file__).resolve().parent
env=os.environ.copy();env['RAYON_NUM_THREADS']='8'
for bits in (29,32):
    for attempt in range(1,4):
        online=threading.Event();stop=threading.Event(); observations=[]
        def monitor():
            while not stop.is_set():
                raw=subprocess.check_output(['ps','-axo','pcpu,comm'],text=True).splitlines()[1:]
                compilers=0;busy=0
                for line in raw:
                    fields=line.strip().split(None,1)
                    if len(fields)!=2: continue
                    cpu,name=fields
                    compilers+=name.endswith('/rustc')
                    busy+=float(cpu)>100 and not name.endswith('/native_compare')
                if online.is_set(): observations.append(dict(compilers=compilers,other_busy_processes=busy))
                stop.wait(.2)
        worker=threading.Thread(target=monitor);worker.start()
        setup_count=0
        with (root/f'quiet-{bits}-{attempt}.jsonl').open('w') as out:
            process=subprocess.Popen(['target/release/examples/native_compare','30',str(bits)],env=env,stdout=subprocess.PIPE,text=True)
            for line in process.stdout:
                out.write(line);out.flush()
                record=json.loads(line)
                if record['kind']=='setup':
                    setup_count+=1
                    if setup_count==2: online.set()
            code=process.wait()
        stop.set();worker.join()
        clean=bool(observations) and all(not x['compilers'] and not x['other_busy_processes'] for x in observations)
        metadata=dict(mask_bits=bits,attempt=attempt,exit_code=code,online_observations=observations,observed_online_quiet=clean)
        (root/f'quiet-{bits}-{attempt}-environment.json').write_text(json.dumps(metadata,indent=2)+'\n')
        print(dict(mask_bits=bits,attempt=attempt,exit_code=code,online_samples=len(observations),observed_online_quiet=clean),flush=True)
        if code: raise SystemExit(code)
        if clean: break
