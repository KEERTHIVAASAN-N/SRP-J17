Cyber Sentry - packaged extension (placeholder TF)

This ZIP includes a fully wired extension that uses a fallback JS ML model so it works without the real TensorFlow runtime.
Files included:
- manifest.json
- background.js
- content.js
- ml_model.js (wrapper)
- phishing_fallback.js (simple JS logistic model)
- libs/tf.min.js (PLACEHOLDER - replace with real tf.min.js)
- model/model.json (present) and model/weights.bin (PLACEHOLDER - replace with real weights.bin)
- popup.html, popup.js, popup.css
- icons/* (placeholders)

To enable real TensorFlow model inference:
1. Download the official TF.js browser bundle (matching model version):
   https://cdn.jsdelivr.net/npm/@tensorflow/tfjs@3.18.0/dist/tf.min.js
   Save it to 'libs/tf.min.js' replacing the placeholder.

2. Replace model/weights.bin with the real binary weights produced by:
   tensorflowjs_converter --input_format=keras path/to/model.h5 path/to/output_folder
   Or obtain your actual weights.bin for the model.json included.

3. Reload the unpacked extension in chrome://extensions.

Notes:
- If the TF model fails to load, the extension uses phishing_fallback.js to provide a reasonable heuristic ML score.
- The content script will compute mlProb using ml_model.js (which loads TF if available) and send it to the background for scoring.
