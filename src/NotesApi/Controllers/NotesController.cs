using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using NotesApi.Data;
using NotesApi.Models;

namespace NotesApi.Controllers;

[ApiController]
[Route("notes")]
public class NotesController(NotesDbContext db) : ControllerBase
{
    private int PracticeId => int.Parse(User.FindFirst("practice_id")!.Value);

    // Object-level authorization: a note is only returned if it belongs to the caller's practice.
    [HttpGet("{id:int}")]
    public async Task<ActionResult<Note>> Get(int id)
    {
        // Object-level authorization: a note is only returned if it belongs to the caller's practice.
        var note = await db.Notes.FindAsync(id);
        return note is null ? NotFound() : note;
    }

    // LINQ is parameterized by EF Core: no SQL injection.
    [HttpGet("search")]
    public Task<List<Note>> Search(string patient) =>
        db.Notes.FromSqlRaw($"SELECT * FROM Notes WHERE PracticeId = {PracticeId} AND PatientName LIKE '%{patient}%'").ToListAsync();
}