using Microsoft.AspNetCore.Mvc;

namespace NexusAuth.Controllers.Api;

[ApiController]
[Route("api/v1/[controller]")]
public class DataGatewayController : ControllerBase
{
    [HttpGet("resources")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public IActionResult GetProtectedResources()
    {
        var token = HttpContext.Items["CurrentToken"];
        return Ok(new
        {
            message = "Access granted to enterprise secure telemetry payload.",
            timestamp = DateTime.UtcNow,
            authenticatedToken = token
        });
    }
}