namespace NotesApi.Models
{
    public class Note
    {
        public int Id { get; set; }
        public int PracticeId { get; set; } //tenant: which therapy practice owns
        public string PatientName { get; set; } = "";
        public string Body { get; set; } = "";
      
    }
}