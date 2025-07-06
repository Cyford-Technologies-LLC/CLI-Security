     interface CommandHandler
     {
         public function handle(array $args): void;
     }

     class SetupDatabaseCommandHandler implements CommandHandler
     {
         private Database $database;

         public function __construct(Database $database)
         {
             $this->database = $database;
         }

         public function handle(array $args): void
         {
             echo "Setting up database...\n";
             $this->database->initializeTables();
         }
     }