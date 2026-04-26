# ecommerce-stack (Shopify)

`ecommerce-stack` is a Go gRPC specialist service used for Shopify storefront follow-up verification checks.

## Included checks

- Shopify `products.json` exposure and structure validation
- Shopify `collections.json` exposure and structure validation
- Shopify `cart.js` accessibility validation
- third-party storefront script domain classification
- missing storefront security headers posture check
- visible Shopify theme/app metadata markers

The service performs safe read-only GET/HEAD checks and reports externally observable posture signals.
