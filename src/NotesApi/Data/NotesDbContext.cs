using Microsoft.EntityFrameworkCore;
using NotesApi.Models;

namespace NotesApi.Data;
public class NotesDbContext(DbContextOptions<NotesDbContext> options) : DbContext(options)
{
    public DbSet<Note> Notes => Set<Note>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Note>().HasData(
            new Note
            {
                Id = 1,
                PracticeId = 1,
                PatientName = "Test Patient A",
                Body = "Synthetic session note 1"
            },
            new Note
            {
                Id = 2,
                PracticeId = 1,
                PatientName = "Test Patient B",
                Body = "Synthetic session note 2"
            },
            new Note
            {
                Id = 3,
                PracticeId = 2,
                PatientName = "Test Patient C",
                Body = "Synthetic session note 3"
            }
        );
    }
}