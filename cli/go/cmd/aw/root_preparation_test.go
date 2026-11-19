package main

import (
 "testing"
 "github.com/spf13/cobra"
)

func TestRootPreparationPolicyNamesIdentityAndMaintenanceBoundaries(t *testing.T) {
 for _, tc := range []struct { name string; command *cobra.Command; want rootPreparationMode }{
  {"offline-verification", verifyCmd, rootPreparationOffline},
  {"offline-audit", auditVerifyCmd, rootPreparationOffline},
  {"neutral-version", versionCmd, rootPreparationNeutral},
  {"activity-producer", activityCmd, rootPreparationLocalOnly},
  {"status-producer", statusCmd, rootPreparationLocalOnly},
  {"certificate-install", teamInstallCertCmd, rootPreparationLocalOnly},
  {"invite-inspection", teamInviteInspectCmd, rootPreparationNoRenewal},
  {"ordinary-request", mailSendCmd, rootPreparationFull},
  {"initialization", initCmd, rootPreparationFull},
 } {
  t.Run(tc.name, func(t *testing.T) {
   got, err := rootPreparationForCommand(tc.command)
   if err != nil || got != tc.want { t.Fatalf("mode=%v err=%v want=%v", got, err, tc.want) }
  })
 }
 parent := &cobra.Command{Use:"producer", Annotations: map[string]string{rootPreparationAnnotation: string(rootPreparationLocalOnly)}}
 child := &cobra.Command{Use:"publish"}; parent.AddCommand(child)
 if got, err := rootPreparationForCommand(child); err != nil || got != rootPreparationLocalOnly { t.Fatalf("producer child=%v %v", got, err) }
 sameName := &cobra.Command{Use:"activity"}
 if got, err := rootPreparationForCommand(sameName); err != nil || got != rootPreparationFull { t.Fatalf("unrelated same-name command=%v %v", got, err) }
}

func TestRootPreparationRejectsAnInvalidPreparationFlag(t *testing.T) {
 command := &cobra.Command{Use:"prepare", Annotations: map[string]string{identityKeyPreparationAnnotation:"key-only"}}
 command.Flags().String("key-only", "", "invalid declaration")
 if err := command.Flags().Set("key-only", "true"); err != nil { t.Fatal(err) }
 if _, err := rootPreparationForCommand(command); err == nil { t.Fatal("invalid preparation flag was silently treated as false") }
}

func TestRootPreparationDoesNotTreatAnExplicitFalseAsOfflinePreparation(t *testing.T) {
 command := &cobra.Command{Use:"prepare", Annotations: map[string]string{identityKeyPreparationAnnotation:"key-only"}}
 command.Flags().Bool("key-only", false, "prepare only")
 if err := command.Flags().Set("key-only", "false"); err != nil { t.Fatal(err) }
 if got, err := rootPreparationForCommand(command); err != nil || got != rootPreparationFull { t.Fatalf("explicit false=%v %v", got, err) }
 if err := command.Flags().Set("key-only", "true"); err != nil { t.Fatal(err) }
 if got, err := rootPreparationForCommand(command); err != nil || got != rootPreparationNeutral { t.Fatalf("explicit true=%v %v", got, err) }
}
