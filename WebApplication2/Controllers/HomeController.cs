using Microsoft.AspNetCore.Mvc;
using nClam;
using System.Diagnostics;
using WebApplication2.Models;

namespace WebApplication2.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _configuration;
        public HomeController(ILogger<HomeController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [HttpGet]
        public ActionResult UploadFile()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> UploadFile(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return Content("file not selected");

            var ms = new MemoryStream();
            file.OpenReadStream().CopyTo(ms);
            byte[] fileBytes = ms.ToArray();

            try
            {
                this._logger.LogInformation("ClamAV scan begin for file {0}", file.FileName);
                var clam = new ClamClient(this._configuration["ClamAVServer:URL"],
                                          Convert.ToInt32(this._configuration["ClamAVServer:Port"]));
                var scanResult = await clam.SendAndScanFileAsync(fileBytes);
                switch (scanResult.Result)
                {
                    case ClamScanResults.Clean:
                        this._logger.LogInformation("The file is clean! ScanResult:{1}", scanResult.RawResult);
                        break;
                    case ClamScanResults.VirusDetected:
                        this._logger.LogError("Virus Found! Virus name: {1}", scanResult.InfectedFiles.FirstOrDefault().VirusName);
                        break;
                    case ClamScanResults.Error:
                        this._logger.LogError("An error occured while scaning the file! ScanResult: {1}", scanResult.RawResult);
                        break;
                    case ClamScanResults.Unknown:
                        this._logger.LogError("Unknown scan result while scaning the file! ScanResult: {0}", scanResult.RawResult);
                        break;
                }
            }
            catch (Exception ex)
            {

                this._logger.LogError("ClamAV Scan Exception: {0}", ex.ToString());
            }
            this._logger.LogInformation("ClamAV scan completed for file {0}", file.FileName);

            return RedirectToAction("Index");
        }
    }
}