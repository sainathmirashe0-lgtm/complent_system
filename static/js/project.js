const video = document.getElementById("video");
const canvas = document.getElementById("canvas");
const snap = document.getElementById("snap");
const photoInput = document.getElementById("photoData");

// Start camera
navigator.mediaDevices.getUserMedia({ video: true })
  .then(stream => {
    video.srcObject = stream;
  })
  .catch(err => {
    alert("Camera access denied!");
  });

// Capture photo
snap.addEventListener("click", () => {
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(video, 0, 0);
  photoInput.value = canvas.toDataURL("image/png");
});

// Get GPS location
navigator.geolocation.getCurrentPosition(
  position => {
    document.getElementById("latitude").value = position.coords.latitude;
    document.getElementById("longitude").value = position.coords.longitude;
  },
  error => {
    alert("Location access denied!");
  }
);
snap.addEventListener("click", () => {
  const maxWidth = 640;
  const scale = maxWidth / video.videoWidth;

  canvas.width = maxWidth;
  canvas.height = video.videoHeight * scale;

  const ctx = canvas.getContext("2d");
  ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

  // JPEG with compression (IMPORTANT)
  photoInput.value = canvas.toDataURL("image/jpeg", 0.6);
});

