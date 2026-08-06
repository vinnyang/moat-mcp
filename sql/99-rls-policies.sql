-- Row-Level Security for the read-only agent role.
-- Enabling RLS hides EVERY row from a non-owner role (deny by default);
-- the SELECT policy below is the explicit grant that reopens the filter.
ALTER TABLE film ENABLE ROW LEVEL SECURITY;

CREATE POLICY film_rating_visible ON film
  FOR SELECT TO mcp_readonly
  USING (rating = 'PG');