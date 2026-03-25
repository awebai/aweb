package main

import (
	"context"
	"fmt"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var contactsAddLabel string

var contactsCmd = &cobra.Command{
	Use:   "contacts",
	Short: "Manage contacts",
}

var contactsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List contacts",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, err := resolveClient()
		if err != nil {
			return err
		}
		resp, err := client.ListContacts(ctx)
		if err != nil {
			return err
		}
		printOutput(resp, formatContactsList)
		return nil
	},
}

var contactsAddCmd = &cobra.Command{
	Use:   "add <address>",
	Short: "Add a contact",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, err := resolveClient()
		if err != nil {
			return err
		}
		resp, err := client.CreateContact(ctx, &awid.ContactCreateRequest{
			ContactAddress: args[0],
			Label:          contactsAddLabel,
		})
		if err != nil {
			return err
		}
		printOutput(resp, formatContactAdd)
		return nil
	},
}

var contactsRemoveCmd = &cobra.Command{
	Use:   "remove <address>",
	Short: "Remove a contact by address",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, err := resolveClient()
		if err != nil {
			return err
		}

		// List contacts to find the ID for the given address.
		list, err := client.ListContacts(ctx)
		if err != nil {
			return err
		}

		address := args[0]
		var contactID string
		for _, c := range list.Contacts {
			if c.ContactAddress == address {
				contactID = c.ContactID
				break
			}
		}
		if contactID == "" {
			return fmt.Errorf("contact not found: %s", address)
		}

		resp, err := client.DeleteContact(ctx, contactID)
		if err != nil {
			return err
		}
		if jsonFlag {
			printJSON(resp)
		} else {
			fmt.Printf("Removed contact %s\n", address)
		}
		return nil
	},
}

func init() {
	contactsAddCmd.Flags().StringVar(&contactsAddLabel, "label", "", "Label for the contact")
	contactsCmd.AddCommand(contactsListCmd)
	contactsCmd.AddCommand(contactsAddCmd)
	contactsCmd.AddCommand(contactsRemoveCmd)
	rootCmd.AddCommand(contactsCmd)
}
