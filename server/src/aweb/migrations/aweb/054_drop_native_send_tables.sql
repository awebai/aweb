-- Retire the native prepared-send outbox. Only the removed NativeMessagingService
-- wrote or read these tables; neither aweb nor aweb Cloud configured it. No CASCADE is used:
-- the mutations table references sends, so it is dropped first.
DROP TABLE IF EXISTS {{tables.human_channel_mutations}};
DROP TABLE IF EXISTS {{tables.human_channel_ingress}};
DROP TABLE IF EXISTS {{tables.human_channel_sends}};
