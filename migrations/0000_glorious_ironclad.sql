CREATE TABLE "live_polls" (
	"id" serial PRIMARY KEY NOT NULL,
	"poll_id" varchar(100) NOT NULL,
	"pass_code" varchar(20) NOT NULL,
	"question" text NOT NULL,
	"creator_id" varchar(50) NOT NULL,
	"is_active" boolean DEFAULT true,
	"allow_multiple_votes" boolean DEFAULT false,
	"created_at" timestamp DEFAULT now(),
	"expires_at" timestamp,
	"message_id" varchar(50),
	"channel_id" varchar(50),
	CONSTRAINT "live_polls_poll_id_unique" UNIQUE("poll_id")
);
--> statement-breakpoint
CREATE TABLE "live_poll_options" (
	"id" serial PRIMARY KEY NOT NULL,
	"poll_id" varchar(100) NOT NULL,
	"option_text" text NOT NULL,
	"option_index" integer NOT NULL,
	"vote_count" integer DEFAULT 0
);
--> statement-breakpoint
CREATE TABLE "live_poll_votes" (
	"id" serial PRIMARY KEY NOT NULL,
	"poll_id" varchar(100) NOT NULL,
	"user_id" varchar(50) NOT NULL,
	"option_index" integer NOT NULL,
	"voted_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "polls" (
	"id" serial PRIMARY KEY NOT NULL,
	"message_id" varchar(50) NOT NULL,
	"channel_id" varchar(50) NOT NULL,
	"guild_id" varchar(50) NOT NULL,
	"question" text NOT NULL,
	"creator_id" varchar(50) NOT NULL,
	"is_active" boolean DEFAULT true,
	"created_at" timestamp DEFAULT now(),
	"expires_at" timestamp,
	"ended" boolean DEFAULT false,
	CONSTRAINT "polls_message_id_unique" UNIQUE("message_id")
);
--> statement-breakpoint
CREATE TABLE "poll_options" (
	"id" serial PRIMARY KEY NOT NULL,
	"message_id" varchar(50) NOT NULL,
	"option_text" text NOT NULL,
	"option_index" integer NOT NULL,
	"emoji" varchar(10) NOT NULL,
	"vote_count" integer DEFAULT 0
);
--> statement-breakpoint
CREATE TABLE "poll_votes" (
	"id" serial PRIMARY KEY NOT NULL,
	"message_id" varchar(50) NOT NULL,
	"user_id" varchar(50) NOT NULL,
	"option_index" integer NOT NULL,
	"voted_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "giveaways" (
	"id" serial PRIMARY KEY NOT NULL,
	"message_id" varchar(50) NOT NULL,
	"channel_id" varchar(50) NOT NULL,
	"guild_id" varchar(50) NOT NULL,
	"prize" text NOT NULL,
	"description" text,
	"winner_count" integer DEFAULT 1,
	"host_id" varchar(50) NOT NULL,
	"is_active" boolean DEFAULT true,
	"ended" boolean DEFAULT false,
	"created_at" timestamp DEFAULT now(),
	"ends_at" timestamp NOT NULL,
	CONSTRAINT "giveaways_message_id_unique" UNIQUE("message_id")
);
--> statement-breakpoint
CREATE TABLE "giveaway_participants" (
	"id" serial PRIMARY KEY NOT NULL,
	"giveaway_id" varchar(50) NOT NULL,
	"user_id" varchar(50) NOT NULL,
	"joined_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "giveaway_winners" (
	"id" serial PRIMARY KEY NOT NULL,
	"giveaway_id" varchar(50) NOT NULL,
	"user_id" varchar(50) NOT NULL,
	"selected_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "user_levels" (
	"id" serial PRIMARY KEY NOT NULL,
	"guild_id" varchar(50) NOT NULL,
	"user_id" varchar(50) NOT NULL,
	"xp" integer DEFAULT 0,
	"level" integer DEFAULT 0,
	"messages" integer DEFAULT 0,
	"last_message" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "user_badges" (
	"id" serial PRIMARY KEY NOT NULL,
	"guild_id" varchar(50) NOT NULL,
	"user_id" varchar(50) NOT NULL,
	"badge_id" varchar(100) NOT NULL,
	"badge_name" varchar(255) NOT NULL,
	"badge_emoji" varchar(10) NOT NULL,
	"badge_color" varchar(50) NOT NULL,
	"badge_description" text NOT NULL,
	"badge_type" varchar(50) NOT NULL,
	"earned_at" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"sid" varchar(255) PRIMARY KEY NOT NULL,
	"sess" text NOT NULL,
	"expire" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" varchar(255) PRIMARY KEY NOT NULL,
	"email" varchar(255),
	"first_name" varchar(255),
	"last_name" varchar(255),
	"profile_image_url" varchar(500),
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
