SELECT
  CONCAT(`usr`.`USER`, '@', `usr`.`HOST`) AS `GRANTEE`
FROM
  `mysql`.`user` AS `usr`
WHERE
    `usr`.`:password_column` = PASSWORD(:password)
    OR
      `usr`.`:password_column` = PASSWORD(UPPER(:password))
    OR
      `usr`.`:password_column` = PASSWORD(
        CONCAT(UPPER(LEFT(:password, 1)), SUBSTRING(:password, 2, LENGTH(:password)))
      );