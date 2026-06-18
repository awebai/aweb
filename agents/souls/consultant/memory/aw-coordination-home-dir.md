# AW Coordination Home Directory

Run `aw` coordination commands only from this agent instance home:

```text
/Users/juanre/prj/awebai/aweb/agents/instances/aweb-consultant
```

Running `aw` from arbitrary repo directories can cause confusing failures such
as AWID registry 503s and may use the wrong workspace identity. Git/file work
can happen in the repo checkout, but mail/chat/task/status commands should be
issued from the instance home.
