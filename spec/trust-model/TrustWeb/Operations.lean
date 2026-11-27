import TrustWeb.Properties

/-!
# Each operation belongs to a team

The team rule, and the results about it.
-/

namespace TrustWeb

/-- For each organisation and kind of act, a team. -/
abbrev Assignment := Org → ActKind → Team

/-- The identity holds a certificate of the team the act is assigned to, and is
valid in the organisation, of some kind. -/
def teamRule (assign : Assignment) : AskRule :=
  fun s o act k => ⟨o, assign o act, k⟩ ∈ s.members ∧ ∃ kind, Valid s o k kind

/-- The admin rule is the team rule with every kind of act of every
organisation assigned to the admin team. -/
theorem adminRule_is_teamRule : adminRule = teamRule (fun _ _ => .admin) := rfl

/-- Any assignment. If a key is with a key holder, `a` holds a certificate of
the team that giving a key back is assigned to in the key's organisation and
is valid in that organisation, and the approvals satisfy its policy for giving
a key back, there is an accepted act under the team rule that `a` asks for,
after which the key is not with a key holder and the identity certificates,
revocations and team certificates are as before. -/
theorem assigned_team_can_take_key_back {assign : Assignment} {s : State} {key : OrgKey}
    {a : Key} {kind : Kind} (hheld : key ∈ s.held)
    (hteam : HasTeamCert s key.org (assign key.org .release) a) (hv : Valid s key.org a kind)
    {approvals : List Key} (happ : Approved s key.org .release approvals) :
    ∃ s', Step (teamRule assign) s (.id a) s' ∧ key ∉ s'.held ∧
      s'.certs = s.certs ∧ s'.revoked = s.revoked ∧ s'.members = s.members := by
  refine ⟨_, Step.release (approvals := approvals) hheld
    (.inr ⟨hheld, a, rfl, ⟨hteam, kind, hv⟩, happ⟩), ?_, rfl, rfl, rfl⟩
  intro hmem
  have := (List.mem_filter.mp hmem).2
  simp at this

/-- Any assignment, in one act. If a key is with a key holder before an
accepted act under the team rule and not after, the asker is the domain owner
of the key's organisation; or an identity that holds a certificate of the team
giving a key back is assigned to and is valid in that organisation; or the key
is a team key of that organisation, and the asker is whoever controls its root
key or an identity that holds a certificate of the team re-keying is assigned
to and is valid in it. -/
theorem only_assigned_team_takes_key_back {assign : Assignment} {s s' : State} {who : Party}
    {key : OrgKey} (hstep : Step (teamRule assign) s who s')
    (hin : key ∈ s.held) (hout : key ∉ s'.held) :
    who = .dns key.org ∨
      (∃ k, who = .id k ∧ HasTeamCert s key.org (assign key.org .release) k ∧
        ∃ kind, Valid s key.org k kind) ∨
      ∃ t, key = .team key.org t ∧
        (who = .controller (.root key.org) ∨
          ∃ k, who = .id k ∧ HasTeamCert s key.org (assign key.org .rekey) k ∧
            ∃ kind, Valid s key.org k kind) := by
  rcases key_leaves_holder_only_three_ways hstep hin hout with
    h | ⟨k, hw, hask⟩ | ⟨t, ht, hw | ⟨k, hw, hask⟩⟩
  · exact .inl h
  · exact .inr (.inl ⟨k, hw, hask.1, hask.2⟩)
  · exact .inr (.inr ⟨t, ht, .inl hw⟩)
  · exact .inr (.inr ⟨t, ht, .inr ⟨k, hw, hask.1, hask.2⟩⟩)

/-- There is an assignment and records `s`, `s1`, `s2` such that 1 holds no
team certificate of organisation 0 in `s` and 0's root key is with a key
holder; an act under the team rule asked for by the holder of invitation
secret 5 takes `s` to `s1`; an act 1 asks for takes `s1` to `s2`; and in `s2`
the root key is not with a key holder. In the construction, giving the root
key back is assigned to team 1, 1 is an agent of 0, and the invitation is to
team 1. `admit`, `invite` and `redeem` exclude the admin team; no premise
excludes a team an act is assigned to. That the route exists for every
assignment and team is not proved. -/
theorem invitation_reaches_an_assigned_team :
    ∃ (assign : Assignment) (s s1 s2 : State),
      (∀ t, ¬ HasTeamCert s 0 t 1) ∧ OrgKey.root 0 ∈ s.held ∧
      Step (teamRule assign) s (.bearer 5) s1 ∧
      Step (teamRule assign) s1 (.id 1) s2 ∧ OrgKey.root 0 ∉ s2.held := by
  let assign : Assignment := fun _ act => if act = .release then .named 1 else .admin
  let c : Cert := ⟨0, 1, .agent, .root⟩
  let i : Invite := ⟨5, 0, .named 1⟩
  let s : State := ⟨[0], [c], [], [], [], [], [.root 0], [], [i], []⟩
  let s1 : State :=
    { s with members := ⟨i.org, i.team, 1⟩ :: s.members,
             invites := s.invites.filter (fun x => decide (x ≠ i)) }
  have hv : Valid s1 0 1 .agent :=
    .agentOfRoot (c := c) (by simp [s1, s]) rfl rfl rfl rfl (by simp [s1, s])
  have hheld : OrgKey.root 0 ∈ s1.held := by simp [s1, s]
  let s2 : State := { s1 with held := s1.held.filter (fun k => decide (k ≠ OrgKey.root 0)) }
  refine ⟨assign, s, s1, s2, ?_, by simp [s], ?_, ?_, ?_⟩
  · intro t h
    simp [HasTeamCert, s] at h
  · exact Step.redeem (i := i) (k := 1) (by simp [s]) (by simp [i]) (.inl ⟨c, by simp [s], rfl⟩)
  · refine Step.release (key := .root 0) (approvals := []) hheld
      (.inr ⟨hheld, 1, rfl, ⟨?_, .agent, hv⟩, ?_⟩)
    · simp [assign, OrgKey.org, s1, s, i]
    · intro r hr
      simp [s1, s] at hr
  · intro hmem
    have := (List.mem_filter.mp hmem).2
    simp at this

/-- For every assignment, organisation `o` and named team `n` such that the
assignment gives admitting an admin in `o` to team `n`, there are records `s`,
`s1`, `s2` such that `s` is reachable under the team rule, `o`'s admin team
key is with a key holder in `s`, and 1 holds no team certificate of `o` in `s`
and is not an admin of `o`; an act under the team rule asked for by the holder
of invitation secret 5 takes `s` to `s1`; an act 1 asks for takes `s1` to
`s2`; and 1 is an admin of `o` in `s2`. In the construction the invitation is
to team `n`, and 1's act is its own admission to the admin team, which the key
holder signs because 1 holds a certificate of team `n`. -/
theorem invitation_then_own_request_makes_an_admin (assign : Assignment) (o n : Nat)
    (hassign : assign o .admitAdmin = .named n) :
    ∃ (s s1 s2 : State),
      Reachable (teamRule assign) s ∧ OrgKey.team o .admin ∈ s.held ∧
      (∀ t, ¬ HasTeamCert s o t 1) ∧ ¬ Admin s o 1 ∧
      Step (teamRule assign) s (.bearer 5) s1 ∧
      Step (teamRule assign) s1 (.id 1) s2 ∧ Admin s2 o 1 := by
  let c : Cert := ⟨o, 1, .agent, .root⟩
  let i : Invite := ⟨5, o, .named n⟩
  let e : State := ⟨[], [], [], [], [], [], [], [], [], []⟩
  let r1s : State := { e with orgs := [o] }
  let r2s : State := { r1s with certs := [c] }
  let r3s : State := { r2s with invites := [i] }
  let s : State := { r3s with held := [.team o .admin] }
  let s1 : State :=
    { s with members := ⟨i.org, i.team, 1⟩ :: s.members,
             invites := s.invites.filter (fun x => decide (x ≠ i)) }
  let ma : Membership := ⟨o, .admin, 1⟩
  let s2 : State := { s1 with members := ma :: s1.members }
  have r1 : Reachable (teamRule assign) r1s :=
    .step (.start []) (Step.createOrg (o := o) (by simp))
  have r2 : Reachable (teamRule assign) r2s :=
    .step r1 (Step.registerByRoot (c := c) (who := .controller (.root o)) (approvals := [])
      rfl (by simp [r1s, c]) (by intro d hd; simp [r1s, e] at hd) (.inl ⟨by simp [r1s, e], rfl⟩))
  have r3 : Reachable (teamRule assign) r3s :=
    .step r2 (Step.invite (i := i) (who := .controller (.team o (.named n))) (approvals := [])
      (by simp [i]) (.inl ⟨by simp [r2s, r1s, e], rfl⟩)
      (by intro j hj; simp [r2s, r1s, e] at hj))
  have rs : Reachable (teamRule assign) s :=
    .step r3 (Step.entrust (key := .team o .admin) (by simp [r3s, r2s, r1s, e]))
  have hv1 : Valid s1 o 1 .agent :=
    .agentOfRoot (c := c) (by simp [s1, s, r3s, r2s]) rfl rfl rfl rfl
      (by simp [s1, s, r3s, r2s, r1s, e])
  have hv2 : Valid s2 o 1 .agent :=
    .agentOfRoot (c := c) (by simp [s2, s1, s, r3s, r2s]) rfl rfl rfl rfl
      (by simp [s2, s1, s, r3s, r2s, r1s, e])
  have nocert : ∀ t, ¬ HasTeamCert s o t 1 := by
    intro t h
    simp [HasTeamCert, s, r3s, r2s, r1s, e] at h
  refine ⟨s, s1, s2, rs, by simp [s], nocert, fun h => nocert .admin h.1, ?_, ?_,
    ⟨by simp [s2, ma], .agent, hv2⟩⟩
  · exact Step.redeem (i := i) (k := 1) (by simp [s, r3s]) (by simp [i])
      (.inl ⟨c, by simp [s, r3s, r2s], rfl⟩)
  · refine Step.admitAdmin (m := ma) (kind := .agent) (approvals := []) rfl hv1
      (.inr ⟨by simp [s1, s, ma], 1, rfl, ⟨?_, .agent, hv1⟩, ?_⟩)
    · simp [hassign, OrgKey.org, s1, s, i, ma]
    · intro r hr
      simp [s1, s, r3s, r2s, r1s, e] at hr

/-- For every assignment, organisation `o` and named team `n` such that the
assignment gives admitting an admin in `o` to team `n`, there are records `s`,
`s1`, `s2`, `s3` such that `s` is reachable under the team rule, `o`'s admin
team key is with a key holder in `s`, 7 has no identity certificate in `s`,
holds no team certificate of `o` there and is valid in no organisation, and 1
is a valid agent of `o` in `s`; an act under the team rule asked for by the
holder of invitation secret 5 takes `s` to `s1`; an act 1 asks for takes `s1`
to `s2`; an act 7 asks for takes `s2` to `s3`; and 7 is an admin of `o` in
`s3`. In the construction the invitation names 7 for team `n`, 1 registers 7
as its own agent, and 7 asks for its own admission to the admin team. -/
theorem outsider_becomes_admin_in_three_acts (assign : Assignment) (o n : Nat)
    (hassign : assign o .admitAdmin = .named n) :
    ∃ (s s1 s2 s3 : State),
      Reachable (teamRule assign) s ∧ OrgKey.team o .admin ∈ s.held ∧
      ¬ Registered s 7 ∧ (∀ t, ¬ HasTeamCert s o t 7) ∧ (∀ o' kind, ¬ Valid s o' 7 kind) ∧
      Valid s o 1 .agent ∧
      Step (teamRule assign) s (.bearer 5) s1 ∧
      Step (teamRule assign) s1 (.id 1) s2 ∧
      Step (teamRule assign) s2 (.id 7) s3 ∧ Admin s3 o 7 := by
  let c : Cert := ⟨o, 1, .agent, .root⟩
  let c7 : Cert := ⟨o, 7, .agent, .member 1⟩
  let i : Invite := ⟨5, o, .named n⟩
  let e : State := ⟨[], [], [], [], [], [], [], [], [], []⟩
  let r1s : State := { e with orgs := [o] }
  let r2s : State := { r1s with certs := [c] }
  let r3s : State := { r2s with invites := [i] }
  let s : State := { r3s with held := [.team o .admin] }
  let s1 : State :=
    { s with members := ⟨i.org, i.team, 7⟩ :: s.members,
             invites := s.invites.filter (fun x => decide (x ≠ i)) }
  let s2 : State := { s1 with certs := c7 :: s1.certs }
  let ma : Membership := ⟨o, .admin, 7⟩
  let s3 : State := { s2 with members := ma :: s2.members }
  have r1 : Reachable (teamRule assign) r1s :=
    .step (.start []) (Step.createOrg (o := o) (by simp))
  have r2 : Reachable (teamRule assign) r2s :=
    .step r1 (Step.registerByRoot (c := c) (who := .controller (.root o)) (approvals := [])
      rfl (by simp [r1s, c]) (by intro d hd; simp [r1s, e] at hd) (.inl ⟨by simp [r1s, e], rfl⟩))
  have r3 : Reachable (teamRule assign) r3s :=
    .step r2 (Step.invite (i := i) (who := .controller (.team o (.named n))) (approvals := [])
      (by simp [i]) (.inl ⟨by simp [r2s, r1s, e], rfl⟩)
      (by intro j hj; simp [r2s, r1s, e] at hj))
  have rs : Reachable (teamRule assign) s :=
    .step r3 (Step.entrust (key := .team o .admin) (by simp [r3s, r2s, r1s, e]))
  have hv : Valid s o 1 .agent :=
    .agentOfRoot (c := c) (by simp [s, r3s, r2s]) rfl rfl rfl rfl (by simp [s, r3s, r2s, r1s, e])
  have hv1 : Valid s1 o 1 .agent :=
    .agentOfRoot (c := c) (by simp [s1, s, r3s, r2s]) rfl rfl rfl rfl
      (by simp [s1, s, r3s, r2s, r1s, e])
  have hv2p : Valid s2 o 1 .agent :=
    .agentOfRoot (c := c) (by simp [s2, s1, s, r3s, r2s]) rfl rfl rfl rfl
      (by simp [s2, s1, s, r3s, r2s, r1s, e])
  have hv2 : Valid s2 o 7 .agent :=
    .agentOf (c := c7) (by simp [s2]) rfl rfl rfl rfl
      (by simp [s2, s1, s, r3s, r2s, r1s, e]) hv2p
  have hv3 : Valid s3 o 7 .agent :=
    Valid.mono (s := s2) (t := s3) (fun _ h => h) (fun _ h => h) hv2
  have nocert7 : ¬ Registered s 7 := by
    intro ⟨d, hd, hds⟩
    simp [s, r3s, r2s, c] at hd
    subst hd
    simp at hds
  refine ⟨s, s1, s2, s3, rs, by simp [s], nocert7, ?_, ?_, hv, ?_, ?_, ?_,
    ⟨by simp [s3, ma], .agent, hv3⟩⟩
  · intro t h
    simp [HasTeamCert, s, r3s, r2s, r1s, e] at h
  · intro o' kind hv'
    obtain ⟨d, hd, hds, _, _⟩ := hv'.cert
    exact nocert7 ⟨d, hd, hds⟩
  · exact Step.redeem (i := i) (k := 7) (by simp [s, r3s]) (by simp [i])
      (.inr (by intro m hm; simp [s, r3s, r2s, r1s, e] at hm))
  · refine Step.registerByParent (c := c7) (p := 1) (pk := .agent) rfl ?_ hv1 (.inr rfl)
    intro d hd
    simp [s1, s, r3s, r2s] at hd
    subst hd
    simp [c, c7]
  · refine Step.admitAdmin (m := ma) (kind := .agent) (approvals := []) rfl hv2
      (.inr ⟨by simp [s2, s1, s, ma], 7, rfl, ⟨?_, .agent, hv2⟩, ?_⟩)
    · simp [hassign, OrgKey.org, s2, s1, s, i, ma]
    · intro r hr
      simp [s2, s1, s, r3s, r2s, r1s, e] at hr

end TrustWeb
