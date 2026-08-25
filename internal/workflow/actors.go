package workflow

// ActorProvided keeps authorization checks explicit at the application boundary.
func ActorProvided(actor string) bool { return len(actor) > 0 }
