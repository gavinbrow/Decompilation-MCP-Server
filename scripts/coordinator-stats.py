"""Linear grouping; metrics semantics preserved from the coordinator."""
def stats(rows):
    # Infrastructure smoke tests are not model performance observations.
    rows=[r for r in rows if not r.get('external_model','').startswith('Non-AI MCP live integration check;')]
    def group(items):
        done = [r for r in items if r.get('done')]
        records = [r['record'] for r in done if r.get('record')]
        usage = [u for r in records for u in r.get('usage', [])]
        cpu_only = [r for r in done if not r.get('record') and (r.get('cpu') or {}).get('outcome')=='match']
        return dict(planned=len(items), completed=len(done),
                    model_completed=len(records),
                    model_uploaded=sum(bool(r.get('submission')) for r in done if r.get('record')),
                    cpu_only_completed=len(cpu_only),
                    cpu_only_uploaded=sum(bool(r.get('submission')) for r in cpu_only),
                    model_matches=sum((r.get('report') or {}).get('outcome')=='match' for r in done),
                    cpu_matches=sum((r.get('cpu') or {}).get('outcome')=='match' for r in done),
                    model_matches_on_cpu_failures=sum((r.get('report') or {}).get('outcome')=='match' and (r.get('cpu') or {}).get('outcome')!='match' for r in done),
                    uploaded=sum(bool(r.get('submission')) for r in done), released=sum(bool(r.get('released')) for r in done),
                    prompt_tokens=sum(u.get('prompt_tokens') or 0 for u in usage),
                    actual_cost_usd=sum(u.get('cost') or 0 for u in usage),
                    cost_measurement_requests=sum(u.get('cost') is not None for u in usage),
                    reasoning_tokens=sum((u.get('completion_tokens_details') or {}).get('reasoning_tokens') or 0 for u in usage),
                    output_tokens=sum(u.get('completion_tokens') or 0 for u in usage),
                    token_measurement_requests=sum(u.get('completion_tokens') is not None for u in usage),
                    mean_attempt_seconds=sum(r.get('elapsed_seconds',0) for r in records)/len(records) if records else None,
                    request_wall_seconds=sum(u.get('client_elapsed_seconds') or 0 for u in usage),
                    ghidra_drafts=sum((r.get('ghidra') or {}).get('outcome')=='draft' for r in items))
    grouped={}
    for row in rows:grouped.setdefault(row.get('model_arm',row['arm']),[]).append(row)
    return {arm:dict(total=group(items),sizes={band:group([r for r in items if r['bucket']==band]) for band in ('up_to_63','64_to_255','256_to_511')}) for arm,items in grouped.items()}
