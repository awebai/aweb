import TrustWeb.Properties

/-!
# Each operation belongs to a team

An `Assignment` names, for each organisation and kind of act, one of its
teams. Under `teamRule` a valid member of the organisation that holds a
certificate of the assigned team may ask. `adminRule` is the team rule with
every act assigned to the admin team (`adminRule_is_teamRule`). How an
assignment is chosen or changed is not modelled: it is a parameter.
-/

namespace TrustWeb

/-- Which team of an organisation may ask for each kind of operation. -/
abbrev Assignment := Org → ActKind → Team

/-- The rule that follows an assignment: a valid member of the organisation
who holds a certificate of the team the operation is assigned to may ask. -/
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

end TrustWeb
